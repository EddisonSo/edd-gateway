package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"eddisonso.com/edd-gateway/internal/k8s"
	"golang.org/x/crypto/ssh"
)

var (
	hostKey     ssh.Signer
	hostKeyOnce sync.Once
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
	clientSigner := k8s.GetClientKey()
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

	// Extract container ID and target user from username
	// Supports formats:
	//   - "containerid" -> user=root, container=containerid
	//   - "user.containerid" -> user=user, container=containerid
	username := sshConn.User()
	targetUser := "root"
	containerID := username

	if idx := strings.LastIndex(username, "."); idx != -1 {
		targetUser = username[:idx]
		containerID = username[idx+1:]
	}

	slog.Info("SSH connection", "container", containerID, "user", targetUser, "client", clientAddr)

	// Resolve container (checks SSH access is enabled)
	container, err := s.router.ResolveSSH(containerID)
	if err != nil {
		slog.Warn("container not found or SSH blocked", "container", containerID, "error", err)
		return
	}

	// Connect to backend container using Kubernetes service DNS
	// Use internal service name instead of external IP for in-cluster routing
	backendAddr := fmt.Sprintf("lb.%s.svc.cluster.local:22", container.Namespace)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("failed to connect to backend", "container", containerID, "addr", backendAddr, "error", err)
		return
	}

	backendConfig := &ssh.ClientConfig{
		User:            targetUser,
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

	// Wait for either connection to close
	done := make(chan struct{}, 2)

	// Wait for client connection to close
	go func() {
		sshConn.Wait()
		slog.Debug("client connection closed")
		done <- struct{}{}
	}()

	// Wait for backend connection to close
	go func() {
		backendSSH.Wait()
		slog.Debug("backend connection closed")
		done <- struct{}{}
	}()

	// Proxy channels between client and backend
	go proxyChannels(chans, backendSSH, sshConn, "client->backend")
	go proxyChannels(backendChans, sshConn, backendSSH, "backend->client")

	// Wait for either connection to close
	<-done
	slog.Debug("SSH session ending", "container", containerID)
	sshConn.Close()
	backendSSH.Close()
}

// proxyChannels forwards SSH channels from source to destination.
// Returns when all channels are processed.
func proxyChannels(chans <-chan ssh.NewChannel, dst ssh.Conn, src ssh.Conn, direction string) {
	for newChan := range chans {
		handleChannel(newChan, dst, src, direction)
	}
}

// handleChannel proxies a single SSH channel and closes connections when done.
func handleChannel(newChan ssh.NewChannel, dst ssh.Conn, src ssh.Conn, direction string) {
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

	// Signal channel for coordinated close
	done := make(chan struct{})
	var closeOnce sync.Once
	closeFn := func() {
		closeOnce.Do(func() {
			slog.Debug("closing channel and connections", "type", chanType)
			srcChan.Close()
			dstChan.Close()
			src.Close()
			dst.Close()
			close(done)
		})
	}

	// Proxy data bidirectionally - don't close on copy completion
	// For exec commands, client stdin may be empty but we need to wait for response
	go func() {
		io.Copy(dstChan, srcChan)
		slog.Debug("client->backend copy done")
		// Don't close here - wait for exit-status
	}()

	go func() {
		io.Copy(srcChan, dstChan)
		slog.Debug("backend->client copy done")
		// Don't close here - wait for exit-status
	}()

	// Proxy requests bidirectionally - close on exit-status
	go proxyRequests(srcReqs, dstChan, closeFn)
	go proxyRequests(dstReqs, srcChan, closeFn)

	// Wait for close to be triggered by exit-status
	<-done
}

// proxyRequests forwards SSH channel requests.
func proxyRequests(reqs <-chan *ssh.Request, dst ssh.Channel, closeChan func()) {
	for req := range reqs {
		slog.Debug("forwarding request", "type", req.Type)
		ok, _ := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok, nil)
		}
		// Close when we receive exit-status (command completed)
		if req.Type == "exit-status" || req.Type == "exit-signal" {
			slog.Debug("received exit, closing")
			closeChan()
			return
		}
	}
	slog.Debug("request channel closed")
}
