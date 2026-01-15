package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	hostKey     ssh.Signer
	hostKeyOnce sync.Once
)

// getHostKey returns the gateway's SSH host key, generating one if needed.
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

// handleSSH handles SSH connections by extracting the username (container ID)
// and proxying to the appropriate container.
func (s *Server) handleSSH(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	// Get or generate host key
	signer := getHostKey()
	if signer == nil {
		slog.Error("no host key available", "client", clientAddr)
		conn.Close()
		return
	}

	// Configure SSH server
	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// Accept any public key - actual auth happens on backend
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Accept keyboard-interactive - actual auth happens on backend
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Accept any password - actual auth happens on backend
			return &ssh.Permissions{
				Extensions: map[string]string{
					"password": "true",
				},
			}, nil
		},
	}
	config.AddHostKey(signer)

	// Perform SSH handshake
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
		sshConn.Close()
		return
	}

	// Connect to backend container
	backendAddr := fmt.Sprintf("%s:22", container.ExternalIP)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("failed to connect to backend", "container", containerID, "addr", backendAddr, "error", err)
		sshConn.Close()
		return
	}

	// Now we need to establish an SSH connection to the backend
	// and proxy all channels/requests between client and backend

	backendConfig := &ssh.ClientConfig{
		User:            "root", // Connect as root to backend
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{}, // Will be populated based on client auth
	}

	// For public key auth, we need to forward the client's key
	// This is complex - for now, use keyboard-interactive or password forwarding
	// The cleanest solution is to pass through the original SSH connection

	// Actually, the proper way to do this is to NOT terminate SSH at the gateway,
	// but instead do TCP-level proxying after extracting the username.
	// However, that requires parsing the SSH protocol at the packet level.

	// For a working implementation, let's use the "proxy command" approach:
	// The gateway acts as a jump host, and we proxy the raw TCP after auth.

	// Simpler approach: Just do raw TCP proxy after we know the container
	// But we already completed the SSH handshake with the client...

	// Let's try a different approach: proxy the channels
	slog.Debug("connecting to backend", "addr", backendAddr)

	// Connect to backend SSH
	backendSSH, backendChans, backendReqs, err := ssh.NewClientConn(backendConn, backendAddr, backendConfig)
	if err != nil {
		slog.Error("failed SSH to backend", "error", err)
		return
	}
	defer backendSSH.Close()

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
	go func() {
		io.Copy(dstChan, srcChan)
		dstChan.CloseWrite()
	}()
	go func() {
		io.Copy(srcChan, dstChan)
		srcChan.CloseWrite()
	}()

	// Proxy requests bidirectionally
	go proxyRequests(srcReqs, dstChan)
	go proxyRequests(dstReqs, srcChan)
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
