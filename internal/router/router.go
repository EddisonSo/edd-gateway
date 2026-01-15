package router

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("container not found")
	ErrNoIP     = errors.New("container has no external IP")
)

// Router resolves container IDs to their network addresses.
type Router struct {
	db    *sql.DB
	cache sync.Map // containerID -> *Container
}

// Container holds routing information for a container.
type Container struct {
	ID         string
	Namespace  string
	ExternalIP string
	Status     string
}

// New creates a router that reads from the compute service database.
func New(dbPath string) (*Router, error) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Router{db: db}, nil
}

// Close closes the database connection.
func (r *Router) Close() error {
	return r.db.Close()
}

// Resolve looks up a container by ID and returns its external IP.
func (r *Router) Resolve(containerID string) (*Container, error) {
	// Check cache first
	if cached, ok := r.cache.Load(containerID); ok {
		c := cached.(*Container)
		if c.ExternalIP != "" && c.Status == "running" {
			return c, nil
		}
	}

	// Query database
	var c Container
	var externalIP sql.NullString
	err := r.db.QueryRow(`
		SELECT id, namespace, external_ip, status
		FROM containers
		WHERE id = ? AND status = 'running'
	`, containerID).Scan(&c.ID, &c.Namespace, &externalIP, &c.Status)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query container: %w", err)
	}

	if !externalIP.Valid || externalIP.String == "" {
		return nil, ErrNoIP
	}
	c.ExternalIP = externalIP.String

	// Update cache
	r.cache.Store(containerID, &c)

	return &c, nil
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
