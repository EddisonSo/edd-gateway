package router

// radixNode is a node in the radix tree.
type radixNode struct {
	prefix   string
	route    *StaticRoute  // nil if this node is not a route endpoint
	children []*radixNode
}

// routeTable provides O(path_length) routing via radix tree.
// Each host has its own radix tree for path matching.
type routeTable struct {
	hosts map[string]*radixNode
}

func newRouteTable() *routeTable {
	return &routeTable{
		hosts: make(map[string]*radixNode),
	}
}

// insert adds a route to the tree.
func (t *routeTable) insert(route *StaticRoute) {
	root, ok := t.hosts[route.Host]
	if !ok {
		root = &radixNode{}
		t.hosts[route.Host] = root
	}
	insert(root, route.PathPrefix, route)
}

func insert(node *radixNode, path string, route *StaticRoute) {
	for {
		if len(path) == 0 {
			node.route = route
			return
		}

		// Find child with matching first character
		var child *radixNode
		var childIdx int
		for i, c := range node.children {
			if len(c.prefix) > 0 && c.prefix[0] == path[0] {
				child = c
				childIdx = i
				break
			}
		}

		if child == nil {
			// No matching child - create new leaf
			node.children = append(node.children, &radixNode{
				prefix: path,
				route:  route,
			})
			return
		}

		// Find common prefix length
		common := commonPrefix(path, child.prefix)

		if common == len(child.prefix) {
			// Child prefix fully matched - descend
			node = child
			path = path[common:]
			continue
		}

		// Partial match - split the child node
		// Before: node -> child("abcd", route1)
		// After:  node -> newChild("ab") -> child("cd", route1)
		//                               \-> newLeaf("xy", route2)  [if path="abxy"]

		newChild := &radixNode{
			prefix:   child.prefix[:common],
			children: []*radixNode{child},
		}
		child.prefix = child.prefix[common:]
		node.children[childIdx] = newChild

		if common == len(path) {
			// The new route ends at the split point
			newChild.route = route
		} else {
			// Add new leaf for remaining path
			newChild.children = append(newChild.children, &radixNode{
				prefix: path[common:],
				route:  route,
			})
		}
		return
	}
}

// lookup finds the longest matching prefix route.
// Returns the route and remaining path after the matched prefix.
// O(path_length) - single traversal.
func (t *routeTable) lookup(host, path string) (*StaticRoute, string) {
	root, ok := t.hosts[host]
	if !ok {
		return nil, path
	}

	var bestRoute *StaticRoute
	var bestLen int
	matched := 0
	node := root

	// Check root
	if node.route != nil {
		bestRoute = node.route
		bestLen = 0
	}

	for len(path) > 0 {
		// Find child matching first character
		var child *radixNode
		for _, c := range node.children {
			if len(c.prefix) > 0 && c.prefix[0] == path[0] {
				child = c
				break
			}
		}

		if child == nil {
			break
		}

		// Check if child prefix matches path
		if len(path) < len(child.prefix) {
			// Path is shorter than prefix - partial match, can't descend
			break
		}

		// Compare prefix
		if path[:len(child.prefix)] != child.prefix {
			// Mismatch - stop here
			break
		}

		// Full prefix match - descend
		matched += len(child.prefix)
		path = path[len(child.prefix):]
		node = child

		if node.route != nil {
			bestRoute = node.route
			bestLen = matched
		}
	}

	if bestRoute == nil {
		return nil, path
	}

	// Calculate remaining path
	remaining := path
	if bestLen == 0 && bestRoute.PathPrefix == "/" {
		// Root matched, remaining is everything after /
	}
	if remaining == "" {
		remaining = "/"
	}

	return bestRoute, remaining
}

// remove deletes a route from the tree.
func (t *routeTable) remove(host, pathPrefix string) bool {
	root, ok := t.hosts[host]
	if !ok {
		return false
	}

	removed := removeNode(root, pathPrefix)

	// Clean up empty host
	if root.route == nil && len(root.children) == 0 {
		delete(t.hosts, host)
	}

	return removed
}

func removeNode(node *radixNode, path string) bool {
	if len(path) == 0 {
		if node.route != nil {
			node.route = nil
			return true
		}
		return false
	}

	for i, child := range node.children {
		if len(child.prefix) > 0 && child.prefix[0] == path[0] {
			if len(path) >= len(child.prefix) && path[:len(child.prefix)] == child.prefix {
				if removeNode(child, path[len(child.prefix):]) {
					// Compact: remove empty leaves, merge single-child nodes
					if child.route == nil && len(child.children) == 0 {
						node.children = append(node.children[:i], node.children[i+1:]...)
					} else if child.route == nil && len(child.children) == 1 {
						only := child.children[0]
						child.prefix = child.prefix + only.prefix
						child.route = only.route
						child.children = only.children
					}
					return true
				}
			}
			break
		}
	}

	return false
}

// commonPrefix returns the length of common prefix between two strings.
func commonPrefix(a, b string) int {
	max := len(a)
	if len(b) < max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return max
}
