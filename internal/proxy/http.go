package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
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

	// Get the ingress port from the connection's local address
	ingressPort := 80
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		ingressPort = addr.Port
	}
	// Normalize internal ports to external ports
	if ingressPort == 8080 {
		ingressPort = 80
	}

	// Extract path from request line
	path := extractRequestPath(headerBuf.String())

	slog.Info("HTTP connection", "host", hostname, "path", path, "port", ingressPort, "client", clientAddr)

	// Try to resolve in order: static routes -> container -> fallback
	var backendAddr string
	var modifiedHeaders []byte

	// 1. Check static routes first
	if route, targetPath, err := s.router.ResolveStaticRoute(hostname, path); err == nil {
		backendAddr = route.Target
		slog.Info("routing HTTP via static route", "host", hostname, "path", path, "target", route.Target, "targetPath", targetPath)

		// If strip_prefix is enabled, rewrite the request path
		if route.StripPrefix && path != targetPath {
			modifiedHeaders = rewriteRequestPath(headerBuf.Bytes(), path, targetPath)
		}
	} else if container, targetPort, err := s.router.ResolveHTTP(hostname, ingressPort); err == nil {
		// 2. Try container routing
		backendAddr = fmt.Sprintf("lb.%s.svc.cluster.local:%d", container.Namespace, targetPort)
		slog.Info("routing HTTP to container", "host", hostname, "container", container.ID, "port", ingressPort, "target", targetPort, "backend", backendAddr)
	} else {
		// 3. Fall back to default upstream
		if s.fallbackAddr == "" {
			slog.Warn("no route found", "host", hostname, "path", path, "port", ingressPort)
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nNo backend available\r\n"))
			conn.Close()
			return
		}
		slog.Debug("routing HTTP to fallback upstream", "host", hostname, "fallback", s.fallbackAddr)
		backendAddr = fmt.Sprintf("%s:%d", s.fallbackAddr, ingressPort)
	}
	backend, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
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

	// Use modified headers if path was rewritten, otherwise use original
	headers := headerBuf.Bytes()
	if modifiedHeaders != nil {
		headers = modifiedHeaders
	}

	// Combine headers with any buffered body data
	initialData := append(headers, buffered...)

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

// extractRequestPath extracts the path from the HTTP request line.
// "GET /foo/bar HTTP/1.1" -> "/foo/bar"
func extractRequestPath(headers string) string {
	// Find the first line (request line)
	idx := strings.Index(headers, "\n")
	if idx == -1 {
		return "/"
	}
	requestLine := strings.TrimSpace(headers[:idx])

	// Parse: METHOD PATH HTTP/VERSION
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return "/"
	}

	path := parts[1]
	// Remove query string if present
	if qIdx := strings.Index(path, "?"); qIdx != -1 {
		path = path[:qIdx]
	}

	if path == "" {
		return "/"
	}
	return path
}

// rewriteRequestPath replaces the path in the HTTP request line.
func rewriteRequestPath(headers []byte, oldPath, newPath string) []byte {
	headerStr := string(headers)

	// Find and replace in the request line only (first line)
	idx := strings.Index(headerStr, "\n")
	if idx == -1 {
		return headers
	}

	requestLine := headerStr[:idx]
	rest := headerStr[idx:]

	// Replace the path in the request line
	newRequestLine := strings.Replace(requestLine, " "+oldPath+" ", " "+newPath+" ", 1)
	// Also handle case where path might have query string
	newRequestLine = strings.Replace(newRequestLine, " "+oldPath+"?", " "+newPath+"?", 1)

	return []byte(newRequestLine + rest)
}
