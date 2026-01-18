package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// handleTLS handles TLS connections by extracting SNI (Server Name Indication)
// from the ClientHello and routing to the appropriate backend.
// If TLS termination is configured, terminates TLS and uses static routes for HTTP.
// Otherwise, passes through to backend (container or fallback).
func (s *Server) handleTLS(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	// Read ClientHello to extract SNI
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		slog.Debug("failed to read TLS header", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	if header[0] != 0x16 {
		slog.Warn("not a TLS handshake", "type", header[0], "client", clientAddr)
		conn.Close()
		return
	}

	length := int(header[3])<<8 | int(header[4])
	if length > 16384 {
		slog.Warn("TLS record too large", "length", length, "client", clientAddr)
		conn.Close()
		return
	}

	payload := make([]byte, length)
	if _, err := readFull(conn, payload); err != nil {
		slog.Debug("failed to read TLS payload", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	sni, err := extractSNI(payload)
	if err != nil {
		slog.Debug("failed to extract SNI", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	ingressPort := 443
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		ingressPort = addr.Port
	}
	if ingressPort == 8443 {
		ingressPort = 443
	}

	slog.Info("TLS connection", "sni", sni, "port", ingressPort, "client", clientAddr)

	// Check if we should terminate TLS (have cert + have static routes for this host)
	if s.tlsConfig != nil && !strings.Contains(sni, ".compute.") {
		// Check if we have static routes for this hostname
		if _, _, err := s.router.ResolveStaticRoute(sni, "/"); err == nil {
			// Terminate TLS and handle as HTTP
			s.handleTLSTermination(conn, header, payload, sni, clientAddr)
			return
		}
	}

	// TLS passthrough for containers or fallback
	var backendAddr string

	if strings.Contains(sni, ".compute.") {
		container, targetPort, err := s.router.ResolveHTTP(sni, ingressPort)
		if err != nil {
			slog.Warn("no ingress rule for port", "sni", sni, "port", ingressPort, "error", err)
			conn.Close()
			return
		}
		backendAddr = fmt.Sprintf("lb.%s.svc.cluster.local:%d", container.Namespace, targetPort)
		slog.Info("TLS passthrough to container", "sni", sni, "port", ingressPort, "target", targetPort)
	} else {
		if s.fallbackAddr == "" {
			slog.Warn("no fallback configured", "sni", sni)
			conn.Close()
			return
		}
		slog.Debug("TLS passthrough to fallback", "sni", sni, "fallback", s.fallbackAddr)
		backendAddr = fmt.Sprintf("%s:%d", s.fallbackAddr, ingressPort)
	}

	backend, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		slog.Error("failed to connect to backend", "sni", sni, "addr", backendAddr, "error", err)
		conn.Close()
		return
	}

	initialData := append(header, payload...)
	proxy(conn, backend, initialData)
}

// handleTLSTermination terminates TLS and handles the decrypted HTTP traffic.
func (s *Server) handleTLSTermination(rawConn net.Conn, header, payload []byte, sni, clientAddr string) {
	// Create a connection that replays the already-read ClientHello
	replayConn := &replayConn{
		Conn:   rawConn,
		replay: append(header, payload...),
	}

	// Wrap with TLS server
	tlsConn := tls.Server(replayConn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("TLS handshake failed", "sni", sni, "error", err, "client", clientAddr)
		rawConn.Close()
		return
	}

	slog.Info("TLS terminated", "sni", sni, "client", clientAddr)

	// Now handle the decrypted connection as HTTP
	s.handleTerminatedHTTP(tlsConn, sni)
}

// handleTerminatedHTTP handles HTTP traffic after TLS termination.
func (s *Server) handleTerminatedHTTP(conn net.Conn, sni string) {
	clientAddr := conn.RemoteAddr().String()
	reader := bufio.NewReader(conn)

	var headerBuf bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			slog.Debug("failed to read HTTP header after TLS termination", "error", err, "client", clientAddr)
			conn.Close()
			return
		}
		headerBuf.WriteString(line)

		if line == "\r\n" || line == "\n" {
			break
		}
		if headerBuf.Len() > 16384 {
			slog.Warn("HTTP headers too large", "client", clientAddr)
			conn.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n\r\n"))
			conn.Close()
			return
		}
	}

	// Extract method and path for detailed logging
	requestLine := extractRequestLine(headerBuf.String())
	path := extractRequestPath(headerBuf.String())
	slog.Info("HTTP after TLS termination", "host", sni, "path", path, "request_line", requestLine, "client", clientAddr)

	// Use static routes for routing
	route, targetPath, err := s.router.ResolveStaticRoute(sni, path)
	if err != nil {
		slog.Warn("no static route found", "host", sni, "path", path, "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n\r\nNo backend available\r\n"))
		conn.Close()
		return
	}

	slog.Info("routing via static route", "host", sni, "path", path, "target", route.Target, "targetPath", targetPath, "strip_prefix", route.StripPrefix, "route_path", route.PathPrefix)

	backend, err := net.DialTimeout("tcp", route.Target, 5*time.Second)
	if err != nil {
		slog.Error("failed to connect to backend", "host", sni, "target", route.Target, "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n\r\nBackend connection failed\r\n"))
		conn.Close()
		return
	}

	// Rewrite path if strip_prefix is enabled
	headers := headerBuf.Bytes()
	if route.StripPrefix && path != targetPath {
		headers = rewriteRequestPath(headers, path, targetPath)
	}

	// Add X-Forwarded-Proto header for TLS-terminated requests
	headers = addHeader(headers, "X-Forwarded-Proto", "https")

	// Get buffered data and proxy
	buffered := make([]byte, reader.Buffered())
	reader.Read(buffered)
	initialData := append(headers, buffered...)

	proxy(conn, backend, initialData)
}

// replayConn replays buffered data before reading from the underlying connection.
type replayConn struct {
	net.Conn
	replay []byte
	offset int
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.offset < len(c.replay) {
		n := copy(b, c.replay[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// extractSNI parses a TLS ClientHello and extracts the SNI hostname.
func extractSNI(payload []byte) (string, error) {
	// Handshake message format:
	// - 1 byte: handshake type (1 = ClientHello)
	// - 3 bytes: length
	// - payload

	if len(payload) < 4 {
		return "", errors.New("payload too short")
	}

	if payload[0] != 0x01 { // ClientHello
		return "", errors.New("not a ClientHello")
	}

	// Skip handshake header
	payload = payload[4:]

	// ClientHello format:
	// - 2 bytes: client version
	// - 32 bytes: random
	// - 1 byte: session ID length
	// - session ID
	// - 2 bytes: cipher suites length
	// - cipher suites
	// - 1 byte: compression methods length
	// - compression methods
	// - 2 bytes: extensions length
	// - extensions

	if len(payload) < 34 {
		return "", errors.New("ClientHello too short")
	}

	// Skip version and random
	payload = payload[34:]

	// Skip session ID
	if len(payload) < 1 {
		return "", errors.New("missing session ID length")
	}
	sessionIDLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sessionIDLen {
		return "", errors.New("truncated session ID")
	}
	payload = payload[sessionIDLen:]

	// Skip cipher suites
	if len(payload) < 2 {
		return "", errors.New("missing cipher suites length")
	}
	cipherLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < cipherLen {
		return "", errors.New("truncated cipher suites")
	}
	payload = payload[cipherLen:]

	// Skip compression methods
	if len(payload) < 1 {
		return "", errors.New("missing compression methods length")
	}
	compLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < compLen {
		return "", errors.New("truncated compression methods")
	}
	payload = payload[compLen:]

	// Parse extensions
	if len(payload) < 2 {
		return "", errors.New("no extensions")
	}
	extLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < extLen {
		return "", errors.New("truncated extensions")
	}

	// Look for SNI extension (type 0x0000)
	for len(payload) >= 4 {
		extType := int(payload[0])<<8 | int(payload[1])
		extDataLen := int(payload[2])<<8 | int(payload[3])
		payload = payload[4:]

		if len(payload) < extDataLen {
			return "", errors.New("truncated extension data")
		}

		if extType == 0x0000 { // SNI
			return parseSNIExtension(payload[:extDataLen])
		}

		payload = payload[extDataLen:]
	}

	return "", errors.New("no SNI extension found")
}

// parseSNIExtension extracts the hostname from an SNI extension.
func parseSNIExtension(data []byte) (string, error) {
	// SNI extension format:
	// - 2 bytes: SNI list length
	// - list of SNI entries:
	//   - 1 byte: name type (0 = hostname)
	//   - 2 bytes: name length
	//   - name

	if len(data) < 2 {
		return "", errors.New("SNI extension too short")
	}

	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) < listLen {
		return "", errors.New("truncated SNI list")
	}

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]

		if len(data) < nameLen {
			return "", errors.New("truncated SNI name")
		}

		if nameType == 0 { // hostname
			hostname := string(data[:nameLen])
			// Validate hostname
			if !isValidHostname(hostname) {
				return "", errors.New("invalid hostname")
			}
			return hostname, nil
		}

		data = data[nameLen:]
	}

	return "", errors.New("no hostname in SNI")
}

// isValidHostname checks if a hostname is valid.
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 255 {
		return false
	}

	// Basic validation - no control characters
	for _, c := range hostname {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}

	// Must have at least one dot
	return bytes.ContainsRune([]byte(hostname), '.')
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
