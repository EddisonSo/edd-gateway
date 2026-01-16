package router

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	ErrNotFound        = errors.New("container not found")
	ErrNoIP            = errors.New("container has no external IP")
	ErrProtocolBlocked = errors.New("protocol access not enabled")
)

// Router resolves container IDs to their network addresses.
// Uses an in-memory cache with periodic sync from PostgreSQL.
type Router struct {
	db     *sql.DB
	cache  sync.Map // containerID -> *Container
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Container holds routing information for a container.
type Container struct {
	ID           string
	Namespace    string
	ExternalIP   string
	Status       string
	SSHEnabled   bool
	HTTPSEnabled bool
}

// New creates a router with in-memory cache backed by PostgreSQL.
func New(connStr string) (*Router, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initial load of all containers into memory
	if err := r.loadAll(); err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("initial load: %w", err)
	}

	// Start background sync
	r.wg.Add(1)
	go r.syncLoop()

	return r, nil
}

// loadAll loads all running containers from the database into memory.
func (r *Router) loadAll() error {
	rows, err := r.db.Query(`
		SELECT id, namespace, external_ip, status,
		       COALESCE(ssh_enabled, false), COALESCE(https_enabled, false)
		FROM containers
		WHERE status = 'running' AND external_ip IS NOT NULL AND external_ip != ''
	`)
	if err != nil {
		return fmt.Errorf("query containers: %w", err)
	}
	defer rows.Close()

	// Build new cache
	newCache := make(map[string]*Container)
	for rows.Next() {
		var c Container
		var externalIP sql.NullString
		if err := rows.Scan(&c.ID, &c.Namespace, &externalIP, &c.Status,
			&c.SSHEnabled, &c.HTTPSEnabled); err != nil {
			return fmt.Errorf("scan container: %w", err)
		}
		if externalIP.Valid && externalIP.String != "" {
			c.ExternalIP = externalIP.String
			newCache[c.ID] = &c
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate containers: %w", err)
	}

	// Clear old entries and add new ones
	r.cache.Range(func(key, value any) bool {
		if _, exists := newCache[key.(string)]; !exists {
			r.cache.Delete(key)
		}
		return true
	})
	for id, c := range newCache {
		r.cache.Store(id, c)
	}

	slog.Debug("loaded containers into cache", "count", len(newCache))
	return nil
}

// syncLoop periodically syncs the cache from the database.
func (r *Router) syncLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if err := r.loadAll(); err != nil {
				slog.Error("failed to sync cache", "error", err)
			}
		}
	}
}

// Close closes the database connection and stops background sync.
func (r *Router) Close() error {
	r.cancel()
	r.wg.Wait()
	return r.db.Close()
}

// Resolve looks up a container by ID from the in-memory cache.
func (r *Router) Resolve(containerID string) (*Container, error) {
	if cached, ok := r.cache.Load(containerID); ok {
		c := cached.(*Container)
		if c.ExternalIP != "" && c.Status == "running" {
			return c, nil
		}
	}
	return nil, ErrNotFound
}

// ResolveByHostname extracts container ID from hostname (e.g., "abc123.cloud.eddisonso.com")
// and resolves it.
func (r *Router) ResolveByHostname(hostname string) (*Container, error) {
	// Extract first subdomain as container ID
	containerID := extractContainerID(hostname)
	if containerID == "" {
		return nil, ErrNotFound
	}
	return r.Resolve(containerID)
}

// extractContainerID extracts the container ID from a hostname.
// "abc123.cloud.eddisonso.com" -> "abc123"
// "cloud.eddisonso.com" -> ""
func extractContainerID(hostname string) string {
	// Count dots to determine if there's a subdomain
	dots := 0
	firstDot := -1
	for i, c := range hostname {
		if c == '.' {
			dots++
			if firstDot == -1 {
				firstDot = i
			}
		}
	}

	// Need at least 3 parts (subdomain.domain.tld)
	if dots < 2 || firstDot <= 0 {
		return ""
	}

	return hostname[:firstDot]
}

// InvalidateCache removes a container from the cache.
func (r *Router) InvalidateCache(containerID string) {
	r.cache.Delete(containerID)
}

// ResolveSSH resolves a container by ID and checks SSH access is enabled.
func (r *Router) ResolveSSH(containerID string) (*Container, error) {
	c, err := r.Resolve(containerID)
	if err != nil {
		return nil, err
	}
	if !c.SSHEnabled {
		return nil, ErrProtocolBlocked
	}
	return c, nil
}

// ResolveHTTPS resolves a container by hostname and checks HTTPS access is enabled.
func (r *Router) ResolveHTTPS(hostname string) (*Container, error) {
	c, err := r.ResolveByHostname(hostname)
	if err != nil {
		return nil, err
	}
	if !c.HTTPSEnabled {
		return nil, ErrProtocolBlocked
	}
	return c, nil
}
