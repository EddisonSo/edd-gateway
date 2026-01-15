package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"eddisonso.com/edd-gateway/internal/router"
)

// Server handles TCP proxying with protocol detection.
type Server struct {
	router    *router.Router
	listeners []net.Listener
	mu        sync.Mutex
	closed    bool
}

// NewServer creates a new proxy server.
func NewServer(r *router.Router) *Server {
	return &Server{
		router: r,
	}
}

// ListenSSH starts the SSH proxy listener.
func (s *Server) ListenSSH(port int) error {
	return s.listen(port, s.handleSSH)
}

// ListenHTTP starts the HTTP proxy listener.
func (s *Server) ListenHTTP(port int) error {
	return s.listen(port, s.handleHTTP)
}

// ListenTLS starts the TLS/HTTPS proxy listener.
func (s *Server) ListenTLS(port int) error {
	return s.listen(port, s.handleTLS)
}

func (s *Server) listen(port int, handler func(net.Conn)) error {
	ln, err := net.Listen("tcp", formatAddr(port))
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()

	slog.Info("listening", "port", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			slog.Error("accept failed", "error", err)
			continue
		}

		go handler(conn)
	}
}

// Close shuts down all listeners.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.mu.Unlock()
}

// proxy copies data bidirectionally between client and backend.
func proxy(client, backend net.Conn, initialData []byte) {
	defer client.Close()
	defer backend.Close()

	// Send any initial data that was read during protocol detection
	if len(initialData) > 0 {
		if _, err := backend.Write(initialData); err != nil {
			slog.Error("failed to write initial data", "error", err)
			return
		}
	}

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backend, client)
		backend.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, backend)
		client.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()

	// Wait for both directions to complete
	<-done
	<-done
}

// dialBackend connects to the container's backend service.
func (s *Server) dialBackend(ip string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(ip, formatPort(port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func formatAddr(port int) string {
	return fmt.Sprintf(":%d", port)
}

func formatPort(port int) string {
	return fmt.Sprintf("%d", port)
}
