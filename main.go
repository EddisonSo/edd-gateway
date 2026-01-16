package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"eddisonso.com/edd-gateway/internal/k8s"
	"eddisonso.com/edd-gateway/internal/proxy"
	"eddisonso.com/edd-gateway/internal/router"
	"eddisonso.com/go-gfs/pkg/gfslog"
)

func main() {
	sshPort := flag.Int("ssh-port", 22, "SSH proxy port")
	httpPort := flag.Int("http-port", 80, "HTTP proxy port")
	httpsPort := flag.Int("https-port", 443, "HTTPS/TLS proxy port")
	fallbackAddr := flag.String("fallback", "", "Fallback upstream for non-container traffic (e.g., 192.168.3.150)")
	logService := flag.String("log-service", "", "Log service address")
	flag.Parse()

	// Logger setup
	logger := gfslog.NewLogger(gfslog.Config{
		Source:         "gateway",
		LogServiceAddr: *logService,
		MinLevel:       slog.LevelDebug,
	})
	slog.SetDefault(logger.Logger)
	defer logger.Close()

	// Initialize SSH client key from K8s Secret
	if err := k8s.InitClientKey(); err != nil {
		slog.Error("failed to initialize SSH client key", "error", err)
		os.Exit(1)
	}

	// Database connection string from environment
	dbConnStr := os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		dbConnStr = "postgres://localhost:5432/eddcloud?sslmode=disable"
	}

	// Router for container lookups
	r, err := router.New(dbConnStr)
	if err != nil {
		slog.Error("failed to create router", "error", err)
		os.Exit(1)
	}
	defer r.Close()

	// Create proxy server
	srv := proxy.NewServer(r, *fallbackAddr)

	// Start SSH listener
	go func() {
		if err := srv.ListenSSH(*sshPort); err != nil {
			slog.Error("SSH listener failed", "error", err)
		}
	}()

	// Start standard HTTP/TLS listeners
	go func() {
		if err := srv.ListenHTTP(*httpPort); err != nil {
			slog.Error("HTTP listener failed", "error", err)
		}
	}()

	go func() {
		if err := srv.ListenTLS(*httpsPort); err != nil {
			slog.Error("TLS listener failed", "error", err)
		}
	}()

	// Start listeners for all configured ingress ports (from database)
	ingressPorts := r.GetAllIngressPorts()
	for _, port := range ingressPorts {
		// Skip standard ports we already listen on
		if port == *httpPort || port == *httpsPort || port == *sshPort {
			continue
		}
		// Start a multi-protocol listener that auto-detects HTTP/TLS
		p := port // capture for goroutine
		go func() {
			if err := srv.ListenMulti(p); err != nil {
				slog.Error("multi listener failed", "port", p, "error", err)
			}
		}()
	}

	slog.Info("gateway started", "ssh", *sshPort, "http", *httpPort, "https", *httpsPort, "ingress_ports", ingressPorts)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("gateway shutting down")
	srv.Close()
}
