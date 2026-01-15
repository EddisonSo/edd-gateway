package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	hostKey       ssh.Signer
	hostKeyOnce   sync.Once
	clientKey     ssh.Signer
	clientKeyOnce sync.Once
)

// getHostKey returns the gateway's SSH host key for server authentication.
func getHostKey() ssh.Signer {
	hostKeyOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			slog.Error("failed to generate host key", "error", err)
			return
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			slog.Error("failed to create signer", "error", err)
			return
		}
		hostKey = signer
		slog.Info("generated SSH host key", "fingerprint", ssh.FingerprintSHA256(hostKey.PublicKey()))
	})
	return hostKey
}

// getClientKey returns the gateway's SSH key for authenticating to backends.
// This key is persisted to /data/gateway_key so it survives restarts.
func getClientKey() ssh.Signer {
	clientKeyOnce.Do(func() {
		keyPath := "/data/gateway_key"
		pubKeyPath := "/data/gateway_key.pub"

		// Try to load existing key
		keyData, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyData)
			if err == nil {
				clientKey = signer
				slog.Info("loaded gateway client key", "fingerprint", ssh.FingerprintSHA256(clientKey.PublicKey()))
				return
			}
			slog.Warn("failed to parse existing key, generating new one", "error", err)
		}

		// Generate new key
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			slog.Error("failed to generate client key", "error", err)
			return
		}

		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			slog.Error("failed to create client signer", "error", err)
			return
		}
		clientKey = signer

		// Save private key in PEM format
		privBytes, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			slog.Error("failed to marshal private key", "error", err)
			return
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(privBytes), 0600); err != nil {
			slog.Error("failed to save private key", "error", err)
			return
		}

		// Save public key in authorized_keys format
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			slog.Error("failed to create ssh public key", "error", err)
			return
		}
		pubKeyData := ssh.MarshalAuthorizedKey(sshPub)
		if err := os.WriteFile(pubKeyPath, pubKeyData, 0644); err != nil {
			slog.Error("failed to save public key", "error", err)
			return
		}

		slog.Info("generated new gateway client key",
			"fingerprint", ssh.FingerprintSHA256(clientKey.PublicKey()),
			"pubkey_path", pubKeyPath)
	})
	return clientKey
}

// GetClientPublicKey returns the gateway's public key in authorized_keys format.
// This is used by the compute service to add to containers.
func GetClientPublicKey() string {
	signer := getClientKey()
	if signer == nil {
		return ""
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

// handleSSH handles SSH connections by extracting the username (container ID)
// and proxying to the appropriate container.
func (s *Server) handleSSH(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	// Get or generate host key
	hostSigner := getHostKey()
	if hostSigner == nil {
		slog.Error("no host key available", "client", clientAddr)
		conn.Close()
		return
	}

	// Get client key for backend auth
	clientSigner := getClientKey()
	if clientSigner == nil {
		slog.Error("no client key available", "client", clientAddr)
		conn.Close()
		return
	}

	// Configure SSH server
	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// Accept any public key - we verify the user owns the container
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	// Perform SSH handshake with client
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		slog.Debug("SSH handshake failed", "error", err, "client", clientAddr)
		return
	}
	defer sshConn.Close()

	// Extract container ID from username
	containerID := sshConn.User()
	slog.Info("SSH connection", "container", containerID, "client", clientAddr)

	// Resolve container
	container, err := s.router.Resolve(containerID)
	if err != nil {
		slog.Warn("container not found", "container", containerID, "error", err)
		return
	}

	// Connect to backend container using gateway's client key
	backendAddr := fmt.Sprintf("%s:22", container.ExternalIP)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("failed to connect to backend", "container", containerID, "addr", backendAddr, "error", err)
		return
	}

	backendConfig := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
	}

	slog.Debug("connecting to backend", "addr", backendAddr)

	// Connect to backend SSH using gateway's key
	backendSSH, backendChans, backendReqs, err := ssh.NewClientConn(backendConn, backendAddr, backendConfig)
	if err != nil {
		slog.Error("failed SSH auth to backend", "container", containerID, "error", err)
		backendConn.Close()
		return
	}
	defer backendSSH.Close()

	slog.Info("proxying SSH session", "container", containerID, "backend", backendAddr)

	// Discard global requests from both sides
	go ssh.DiscardRequests(reqs)
	go ssh.DiscardRequests(backendReqs)

	// Proxy channels between client and backend
	go proxyChannels(chans, backendSSH, sshConn, "client->backend")
	proxyChannels(backendChans, sshConn, backendSSH, "backend->client")
}

// proxyChannels forwards SSH channels from source to destination.
func proxyChannels(chans <-chan ssh.NewChannel, dst ssh.Conn, src ssh.Conn, direction string) {
	for newChan := range chans {
		go handleChannel(newChan, dst, direction)
	}
}

// handleChannel proxies a single SSH channel.
func handleChannel(newChan ssh.NewChannel, dst ssh.Conn, direction string) {
	chanType := newChan.ChannelType()
	extraData := newChan.ExtraData()

	slog.Debug("proxying channel", "type", chanType, "direction", direction)

	// Open corresponding channel on destination
	dstChan, dstReqs, err := dst.OpenChannel(chanType, extraData)
	if err != nil {
		slog.Error("failed to open channel on dst", "type", chanType, "error", err)
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	srcChan, srcReqs, err := newChan.Accept()
	if err != nil {
		slog.Error("failed to accept channel", "type", chanType, "error", err)
		dstChan.Close()
		return
	}

	// Proxy data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(dstChan, srcChan)
		dstChan.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(srcChan, dstChan)
		srcChan.CloseWrite()
	}()

	// Proxy requests bidirectionally
	go proxyRequests(srcReqs, dstChan)
	go proxyRequests(dstReqs, srcChan)

	wg.Wait()
}

// proxyRequests forwards SSH channel requests.
func proxyRequests(reqs <-chan *ssh.Request, dst ssh.Channel) {
	for req := range reqs {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			slog.Debug("request forward failed", "type", req.Type, "error", err)
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}
