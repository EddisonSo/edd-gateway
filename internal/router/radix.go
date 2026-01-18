package router

import "strings"

// routeTable provides O(1) host lookup + O(path_depth) prefix matching.
// Simple and effective for typical URL paths (3-5 segments deep).
type routeTable struct {
	// host -> (path prefix -> route)
	hosts map[string]map[string]*StaticRoute
}

func newRouteTable() *routeTable {
	return &routeTable{
		hosts: make(map[string]map[string]*StaticRoute),
	}
}

// insert adds a route to the table.
func (t *routeTable) insert(route *StaticRoute) {
	paths, ok := t.hosts[route.Host]
	if !ok {
		paths = make(map[string]*StaticRoute)
		t.hosts[route.Host] = paths
	}
	paths[route.PathPrefix] = route
}

// lookup finds the longest matching prefix for the given host and path.
// Walks up the path hierarchy: /a/b/c -> /a/b -> /a -> /
// Returns the matched route and the remaining path after the prefix.
func (t *routeTable) lookup(host, path string) (*StaticRoute, string) {
	paths, ok := t.hosts[host]
	if !ok {
		return nil, path
	}

	// Try exact match first, then walk up
	current := path
	for {
		if route, ok := paths[current]; ok {
			remaining := strings.TrimPrefix(path, current)
			if remaining == "" {
				remaining = "/"
			}
			return route, remaining
		}

		if current == "/" {
			break
		}

		// Move up one path segment
		idx := strings.LastIndex(current, "/")
		if idx <= 0 {
			current = "/"
		} else {
			current = current[:idx]
		}
	}

	return nil, path
}

// remove deletes a route from the table.
func (t *routeTable) remove(host, pathPrefix string) bool {
	paths, ok := t.hosts[host]
	if !ok {
		return false
	}

	if _, exists := paths[pathPrefix]; !exists {
		return false
	}

	delete(paths, pathPrefix)

	if len(paths) == 0 {
		delete(t.hosts, host)
	}

	return true
}

// clear removes all routes.
func (t *routeTable) clear() {
	t.hosts = make(map[string]map[string]*StaticRoute)
}
