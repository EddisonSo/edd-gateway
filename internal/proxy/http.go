package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// handleHTTP handles HTTP connections by extracting the Host header
// and routing to the appropriate container.
func (s *Server) handleHTTP(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	// Read HTTP request line and headers
	reader := bufio.NewReader(conn)

	// Read until we have the complete headers (ends with \r\n\r\n)
	var headerBuf bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			slog.Debug("failed to read HTTP header", "error", err, "client", clientAddr)
			conn.Close()
			return
		}
		headerBuf.WriteString(line)

		// End of headers
		if line == "\r\n" || line == "\n" {
			break
		}

		// Safety limit
		if headerBuf.Len() > 16384 {
			slog.Warn("HTTP headers too large", "client", clientAddr)
			conn.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"))
			conn.Close()
			return
		}
	}

	// Parse Host header
	host := extractHostHeader(headerBuf.String())
	if host == "" {
		slog.Warn("no Host header in HTTP request", "client", clientAddr)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header\r\n"))
		conn.Close()
		return
	}

	// Remove port from host if present
	hostname := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
	}

	slog.Info("HTTP connection", "host", hostname, "client", clientAddr)

	// Resolve container from hostname
	container, err := s.router.ResolveByHostname(hostname)
	if err != nil {
		slog.Warn("container not found for Host", "host", hostname, "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nContainer not found\r\n"))
		conn.Close()
		return
	}

	// Connect to backend (using port 80 for HTTP)
	backendAddr := fmt.Sprintf("%s:80", container.ExternalIP)
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		slog.Error("failed to connect to backend", "host", hostname, "addr", backendAddr, "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nBackend connection failed\r\n"))
		conn.Close()
		return
	}

	slog.Debug("proxying HTTP to backend", "host", hostname, "backend", backendAddr)

	// Get any buffered data from the reader
	buffered := make([]byte, reader.Buffered())
	reader.Read(buffered)

	// Combine headers with any buffered body data
	initialData := append(headerBuf.Bytes(), buffered...)

	// Proxy the connection
	proxy(conn, backend, initialData)
}

// extractHostHeader finds the Host header value in HTTP headers.
func extractHostHeader(headers string) string {
	lines := strings.Split(headers, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}
