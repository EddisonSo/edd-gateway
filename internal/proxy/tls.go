package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// handleTLS handles TLS connections by extracting SNI (Server Name Indication)
// from the ClientHello and routing to the appropriate container.
// The TLS connection is NOT terminated - it's passed through to the backend.
func (s *Server) handleTLS(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	// Read ClientHello to extract SNI
	// TLS record format:
	// - 1 byte: content type (22 = handshake)
	// - 2 bytes: version
	// - 2 bytes: length
	// - payload

	// Read the TLS record header
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		slog.Debug("failed to read TLS header", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	// Verify it's a TLS handshake
	if header[0] != 0x16 { // handshake
		slog.Warn("not a TLS handshake", "type", header[0], "client", clientAddr)
		conn.Close()
		return
	}

	// Get payload length
	length := int(header[3])<<8 | int(header[4])
	if length > 16384 {
		slog.Warn("TLS record too large", "length", length, "client", clientAddr)
		conn.Close()
		return
	}

	// Read the handshake payload
	payload := make([]byte, length)
	if _, err := readFull(conn, payload); err != nil {
		slog.Debug("failed to read TLS payload", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	// Parse ClientHello to extract SNI
	sni, err := extractSNI(payload)
	if err != nil {
		slog.Debug("failed to extract SNI", "error", err, "client", clientAddr)
		conn.Close()
		return
	}

	// Get the ingress port from the connection's local address
	ingressPort := 443
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		ingressPort = addr.Port
	}
	// Normalize internal port to external port
	if ingressPort == 8443 {
		ingressPort = 443
	}

	slog.Info("TLS connection", "sni", sni, "port", ingressPort, "client", clientAddr)

	var backendAddr string

	// Try to resolve in order: container -> fallback
	// Note: Static routes are for HTTP (after TLS termination), not TLS passthrough
	// TLS passthrough goes to fallback (Traefik) for TLS termination

	if strings.Contains(sni, ".compute.") {
		// 1. Check if this is a container hostname (*.compute.eddisonso.com)
		container, targetPort, err := s.router.ResolveHTTP(sni, ingressPort)
		if err != nil {
			// No ingress rule for this port - drop connection
			slog.Warn("no ingress rule for port", "sni", sni, "port", ingressPort, "error", err)
			conn.Close()
			return
		}
		backendAddr = fmt.Sprintf("lb.%s.svc.cluster.local:%d", container.Namespace, targetPort)
		slog.Info("routing TLS to container", "sni", sni, "port", ingressPort, "target", targetPort)
	} else {
		// 2. Non-container hostname - route to fallback upstream (Traefik for TLS termination)
		if s.fallbackAddr == "" {
			slog.Warn("no fallback configured for non-container hostname", "sni", sni)
			conn.Close()
			return
		}
		slog.Debug("routing to fallback upstream", "sni", sni, "port", ingressPort, "fallback", s.fallbackAddr)
		backendAddr = fmt.Sprintf("%s:%d", s.fallbackAddr, ingressPort)
	}
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("failed to connect to backend", "sni", sni, "addr", backendAddr, "error", err)
		conn.Close()
		return
	}

	slog.Debug("proxying TLS to backend", "sni", sni, "backend", backendAddr)

	// Proxy the connection, including the already-read header and payload
	initialData := append(header, payload...)
	proxy(conn, backend, initialData)
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
