package router

// DefaultCacheSize is the default number of recent lookups to cache.
const DefaultCacheSize = 512

// radixNode is a node in the radix tree.
type radixNode struct {
	prefix   string
	route    *StaticRoute // nil if this node is not a route endpoint
	children []*radixNode
}

// cacheEntry stores a cached lookup result.
type cacheEntry struct {
	route     *StaticRoute
	remaining string
}

// lruNode is a node in the LRU doubly-linked list.
type lruNode struct {
	key   string // "host:path"
	value cacheEntry
	prev  *lruNode
	next  *lruNode
}

// lruCache is a fixed-size LRU cache for route lookups.
type lruCache struct {
	capacity int
	items    map[string]*lruNode
	head     *lruNode // most recent
	tail     *lruNode // least recent
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		items:    make(map[string]*lruNode, capacity),
	}
}

func (c *lruCache) get(key string) (cacheEntry, bool) {
	node, ok := c.items[key]
	if !ok {
		return cacheEntry{}, false
	}
	c.moveToFront(node)
	return node.value, true
}

func (c *lruCache) put(key string, value cacheEntry) {
	if node, ok := c.items[key]; ok {
		node.value = value
		c.moveToFront(node)
		return
	}

	node := &lruNode{key: key, value: value}
	c.items[key] = node
	c.addToFront(node)

	if len(c.items) > c.capacity {
		c.removeLast()
	}
}

func (c *lruCache) clear() {
	c.items = make(map[string]*lruNode, c.capacity)
	c.head = nil
	c.tail = nil
}

func (c *lruCache) moveToFront(node *lruNode) {
	if node == c.head {
		return
	}
	c.remove(node)
	c.addToFront(node)
}

func (c *lruCache) addToFront(node *lruNode) {
	node.prev = nil
	node.next = c.head
	if c.head != nil {
		c.head.prev = node
	}
	c.head = node
	if c.tail == nil {
		c.tail = node
	}
}

func (c *lruCache) remove(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		c.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		c.tail = node.prev
	}
}

func (c *lruCache) removeLast() {
	if c.tail == nil {
		return
	}
	delete(c.items, c.tail.key)
	c.remove(c.tail)
}

// routeTable provides O(path_length) routing via radix tree.
// Each host has its own radix tree for path matching.
// Includes an LRU cache for hot paths.
type routeTable struct {
	hosts     map[string]*radixNode
	cache     *lruCache
	cacheSize int
}

func newRouteTable() *routeTable {
	return newRouteTableWithCacheSize(DefaultCacheSize)
}

func newRouteTableWithCacheSize(cacheSize int) *routeTable {
	return &routeTable{
		hosts:     make(map[string]*radixNode),
		cache:     newLRUCache(cacheSize),
		cacheSize: cacheSize,
	}
}

// insert adds a route to the tree and clears the cache.
func (t *routeTable) insert(route *StaticRoute) {
	root, ok := t.hosts[route.Host]
	if !ok {
		root = &radixNode{}
		t.hosts[route.Host] = root
	}
	insert(root, route.PathPrefix, route)
	t.cache.clear() // Invalidate cache on route change
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
// Checks LRU cache first for O(1) hot path lookup, falls back to
// O(path_length) radix tree traversal on cache miss.
func (t *routeTable) lookup(host, path string) (*StaticRoute, string) {
	// Check cache first
	cacheKey := host + ":" + path
	if entry, ok := t.cache.get(cacheKey); ok {
		return entry.route, entry.remaining
	}

	// Cache miss - traverse radix tree
	root, ok := t.hosts[host]
	if !ok {
		return nil, path
	}

	var bestRoute *StaticRoute
	var bestLen int
	matched := 0
	node := root
	remainingPath := path

	// Check root
	if node.route != nil {
		bestRoute = node.route
		bestLen = 0
	}

	for len(remainingPath) > 0 {
		// Find child matching first character
		var child *radixNode
		for _, c := range node.children {
			if len(c.prefix) > 0 && c.prefix[0] == remainingPath[0] {
				child = c
				break
			}
		}

		if child == nil {
			break
		}

		// Check if child prefix matches path
		if len(remainingPath) < len(child.prefix) {
			// Path is shorter than prefix - partial match, can't descend
			break
		}

		// Compare prefix
		if remainingPath[:len(child.prefix)] != child.prefix {
			// Mismatch - stop here
			break
		}

		// Full prefix match - descend
		matched += len(child.prefix)
		remainingPath = remainingPath[len(child.prefix):]
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
	remaining := remainingPath
	if bestLen == 0 && bestRoute.PathPrefix == "/" {
		// Root matched, remaining is everything after /
	}
	if remaining == "" {
		remaining = "/"
	}

	// Add to cache
	t.cache.put(cacheKey, cacheEntry{route: bestRoute, remaining: remaining})

	return bestRoute, remaining
}

// remove deletes a route from the tree and clears the cache.
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

	if removed {
		t.cache.clear() // Invalidate cache on route change
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
