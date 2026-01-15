package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"eddisonso.com/edd-gateway/internal/proxy"
	"eddisonso.com/edd-gateway/internal/router"
	"eddisonso.com/go-gfs/pkg/gfslog"
)

func main() {
	computeDB := flag.String("compute-db", "/data/compute.db", "Path to compute service database")
	sshPort := flag.Int("ssh-port", 22, "SSH proxy port")
	httpPort := flag.Int("http-port", 80, "HTTP proxy port")
	httpsPort := flag.Int("https-port", 443, "HTTPS/TLS proxy port")
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

	// Router for container lookups
	r, err := router.New(*computeDB)
	if err != nil {
		slog.Error("failed to create router", "error", err)
		os.Exit(1)
	}
	defer r.Close()

	// Create proxy server
	srv := proxy.NewServer(r)

	// Start listeners
	go func() {
		if err := srv.ListenSSH(*sshPort); err != nil {
			slog.Error("SSH listener failed", "error", err)
		}
	}()

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

	slog.Info("gateway started", "ssh", *sshPort, "http", *httpPort, "https", *httpsPort)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("gateway shutting down")
	srv.Close()
}
