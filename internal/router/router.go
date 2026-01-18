package router

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	ErrNotFound        = errors.New("container not found")
	ErrNoIP            = errors.New("container has no external IP")
	ErrProtocolBlocked = errors.New("protocol access not enabled")
	ErrNoRoute         = errors.New("no matching route")
)

// StaticRoute holds routing info for a static path-based route.
type StaticRoute struct {
	ID          int
	Host        string // e.g., "cloud-api.eddisonso.com"
	PathPrefix  string // e.g., "/compute" or "/"
	Target      string // e.g., "edd-compute:80"
	StripPrefix bool   // Whether to strip the path prefix when proxying
	Priority    int    // Higher priority = matched first (longer paths get higher priority)
}

// Router resolves container IDs to their network addresses.
// Uses an in-memory cache with periodic sync from PostgreSQL.
type Router struct {
	db         *sql.DB
	cache      sync.Map       // containerID -> *Container
	routeTable *routeTable    // radix tree for path routing
	routesList []StaticRoute  // flat list for ListRoutes()
	routesMu   sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// Container holds routing information for a container.
type Container struct {
	ID           string
	Namespace    string
	ExternalIP   string
	Status       string
	SSHEnabled   bool
	HTTPSEnabled bool
	PortMap      map[int]int // ingress port -> target port
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

	// Ensure static_routes table exists
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS static_routes (
			id SERIAL PRIMARY KEY,
			host TEXT NOT NULL,
			path_prefix TEXT NOT NULL,
			target TEXT NOT NULL,
			strip_prefix BOOLEAN NOT NULL DEFAULT false,
			priority INT NOT NULL DEFAULT 0,
			UNIQUE(host, path_prefix)
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create static_routes table: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initial load of all containers and routes into memory
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
	// Load containers
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
			c.PortMap = make(map[int]int)
			newCache[c.ID] = &c
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate containers: %w", err)
	}

	// Load ingress rules for all containers
	ruleRows, err := r.db.Query(`
		SELECT container_id, port, target_port FROM ingress_rules
	`)
	if err != nil {
		return fmt.Errorf("query ingress rules: %w", err)
	}
	defer ruleRows.Close()

	for ruleRows.Next() {
		var containerID string
		var port, targetPort int
		if err := ruleRows.Scan(&containerID, &port, &targetPort); err != nil {
			return fmt.Errorf("scan ingress rule: %w", err)
		}
		if c, exists := newCache[containerID]; exists {
			c.PortMap[port] = targetPort
		}
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

	// Load static routes into radix tree
	routeRows, err := r.db.Query(`
		SELECT id, host, path_prefix, target, strip_prefix, priority
		FROM static_routes
	`)
	if err != nil {
		return fmt.Errorf("query static routes: %w", err)
	}
	defer routeRows.Close()

	newTable := newRouteTable()
	var routes []StaticRoute
	for routeRows.Next() {
		var route StaticRoute
		if err := routeRows.Scan(&route.ID, &route.Host, &route.PathPrefix,
			&route.Target, &route.StripPrefix, &route.Priority); err != nil {
			return fmt.Errorf("scan static route: %w", err)
		}
		routes = append(routes, route)
		newTable.insert(&routes[len(routes)-1])
	}
	if err := routeRows.Err(); err != nil {
		return fmt.Errorf("iterate static routes: %w", err)
	}

	r.routesMu.Lock()
	r.routeTable = newTable
	r.routesList = routes
	r.routesMu.Unlock()

	// Log all loaded routes for debugging
	for _, route := range routes {
		slog.Debug("loaded route", "host", route.Host, "path", route.PathPrefix, "target", route.Target, "strip_prefix", route.StripPrefix)
	}
	slog.Debug("loaded static routes into cache", "count", len(routes))
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

// ResolveHTTP resolves a container by hostname for a given ingress port.
// Returns the container and target port if the ingress port is configured.
func (r *Router) ResolveHTTP(hostname string, ingressPort int) (*Container, int, error) {
	c, err := r.ResolveByHostname(hostname)
	if err != nil {
		return nil, 0, err
	}
	targetPort, ok := c.PortMap[ingressPort]
	if !ok {
		return nil, 0, ErrProtocolBlocked
	}
	return c, targetPort, nil
}

// GetAllIngressPorts returns all unique ingress ports configured across all containers.
func (r *Router) GetAllIngressPorts() []int {
	portSet := make(map[int]bool)
	r.cache.Range(func(key, value any) bool {
		c := value.(*Container)
		for port := range c.PortMap {
			portSet[port] = true
		}
		return true
	})
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	return ports
}

// RegisterRoute adds or updates a static route in the database.
// Priority is automatically set based on path length (longer paths = higher priority).
func (r *Router) RegisterRoute(host, pathPrefix, target string, stripPrefix bool) error {
	// Auto-calculate priority based on path specificity
	priority := len(pathPrefix) * 10
	if pathPrefix == "/" {
		priority = 0 // Catch-all has lowest priority
	}

	_, err := r.db.Exec(`
		INSERT INTO static_routes (host, path_prefix, target, strip_prefix, priority)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (host, path_prefix) DO UPDATE SET
			target = EXCLUDED.target,
			strip_prefix = EXCLUDED.strip_prefix,
			priority = EXCLUDED.priority
	`, host, pathPrefix, target, stripPrefix, priority)
	if err != nil {
		return fmt.Errorf("insert static route: %w", err)
	}

	// Reload routes into cache
	return r.loadStaticRoutes()
}

// UnregisterRoute removes a static route from the database.
func (r *Router) UnregisterRoute(host, pathPrefix string) error {
	result, err := r.db.Exec(`
		DELETE FROM static_routes WHERE host = $1 AND path_prefix = $2
	`, host, pathPrefix)
	if err != nil {
		return fmt.Errorf("delete static route: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNoRoute
	}

	// Reload routes into cache
	return r.loadStaticRoutes()
}

// loadStaticRoutes reloads just the static routes from the database.
func (r *Router) loadStaticRoutes() error {
	routeRows, err := r.db.Query(`
		SELECT id, host, path_prefix, target, strip_prefix, priority
		FROM static_routes
	`)
	if err != nil {
		return fmt.Errorf("query static routes: %w", err)
	}
	defer routeRows.Close()

	// Build new route table
	newTable := newRouteTable()
	var routes []StaticRoute

	for routeRows.Next() {
		var route StaticRoute
		if err := routeRows.Scan(&route.ID, &route.Host, &route.PathPrefix,
			&route.Target, &route.StripPrefix, &route.Priority); err != nil {
			return fmt.Errorf("scan static route: %w", err)
		}
		routes = append(routes, route)
		newTable.insert(&routes[len(routes)-1])
	}

	r.routesMu.Lock()
	r.routeTable = newTable
	r.routesList = routes
	r.routesMu.Unlock()

	slog.Info("reloaded static routes", "count", len(routes))
	return nil
}

// ResolveStaticRoute finds a matching static route for the given host and path.
// Uses radix tree for O(path_length) lookup.
// Returns the route and the path to use (with prefix stripped if configured).
func (r *Router) ResolveStaticRoute(host, path string) (*StaticRoute, string, error) {
	r.routesMu.RLock()
	defer r.routesMu.RUnlock()

	if r.routeTable == nil {
		slog.Debug("route resolution: routeTable is nil", "host", host, "path", path)
		return nil, "", ErrNoRoute
	}

	slog.Debug("route resolution: looking up", "host", host, "path", path, "known_hosts", len(r.routeTable.hosts))

	route, remaining := r.routeTable.lookup(host, path)
	if route == nil {
		slog.Debug("route resolution: no route found", "host", host, "path", path)
		return nil, "", ErrNoRoute
	}

	slog.Debug("route resolution: found match", "host", host, "path", path, "matched_prefix", route.PathPrefix, "target", route.Target, "remaining", remaining)

	targetPath := path
	if route.StripPrefix && route.PathPrefix != "/" {
		targetPath = remaining
		if targetPath == "" {
			targetPath = "/"
		}
	}

	return route, targetPath, nil
}

// ListRoutes returns all configured static routes.
func (r *Router) ListRoutes() []StaticRoute {
	r.routesMu.RLock()
	defer r.routesMu.RUnlock()

	// Return a copy to avoid race conditions
	routes := make([]StaticRoute, len(r.routesList))
	copy(routes, r.routesList)

	// Sort by host, then path for display
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Host != routes[j].Host {
			return routes[i].Host < routes[j].Host
		}
		return routes[i].PathPrefix < routes[j].PathPrefix
	})

	return routes
}
