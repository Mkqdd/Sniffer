package cache

import (
	"sync"
	"sync/atomic"
)

// Ring is a lock-free circular buffer with fixed capacity
// 无锁环形缓冲区
type Ring struct {
	capacity int
	items    []interface{}
	head     atomic.Uint32 // Write position
	tail     atomic.Uint32 // Read position (for snapshot)
	count    atomic.Int32  // Current count
}

// New creates a new Ring with the specified capacity
func New(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Ring{
		capacity: capacity,
		items:    make([]interface{}, capacity),
	}
}

// Push adds an item to the ring buffer
// If the buffer is full, it overwrites the oldest item
func (r *Ring) Push(item interface{}) {
	// Get current head position and increment
	pos := r.head.Add(1) - 1
	idx := int(pos) % r.capacity

	// Store the item
	r.items[idx] = item

	// Update count (capped at capacity)
	for {
		current := r.count.Load()
		if current >= int32(r.capacity) {
			// Already at capacity, no need to increment
			break
		}
		if r.count.CompareAndSwap(current, current+1) {
			break
		}
	}
}

// Snapshot returns a copy of all current items
// This operation is thread-safe but may see partial updates
func (r *Ring) Snapshot() []interface{} {
	count := int(r.count.Load())
	if count == 0 {
		return nil
	}

	result := make([]interface{}, 0, count)
	head := int(r.head.Load())

	// Read from tail to head
	if count < r.capacity {
		// Not full yet, read from 0 to head
		for i := 0; i < count; i++ {
			if item := r.items[i]; item != nil {
				result = append(result, item)
			}
		}
	} else {
		// Full, read in circular order
		start := head % r.capacity
		for i := 0; i < r.capacity; i++ {
			idx := (start + i) % r.capacity
			if item := r.items[idx]; item != nil {
				result = append(result, item)
			}
		}
	}

	return result
}

// Len returns the current number of items
func (r *Ring) Len() int {
	return int(r.count.Load())
}

// Clear removes all items from the ring buffer
func (r *Ring) Clear() {
	for i := range r.items {
		r.items[i] = nil
	}
	r.head.Store(0)
	r.count.Store(0)
}

// Cap returns the capacity of the ring buffer
func (r *Ring) Cap() int {
	return r.capacity
}

// Resize creates a new Ring with the new capacity and migrates data
// Returns the new Ring (double-buffer pattern for smooth migration)
func (r *Ring) Resize(newCapacity int) *Ring {
	if newCapacity <= 0 {
		newCapacity = 1000
	}

	// Create new ring
	newRing := New(newCapacity)

	// Snapshot current data
	snapshot := r.Snapshot()

	// Migrate data to new ring
	// If new capacity is smaller, only keep the most recent items
	start := 0
	if len(snapshot) > newCapacity {
		start = len(snapshot) - newCapacity
	}

	for i := start; i < len(snapshot); i++ {
		newRing.Push(snapshot[i])
	}

	return newRing
}

// RingSet manages multiple Ring buffers with atomic swapping
// 环形缓冲区集合，支持原子替换
type RingSet struct {
	mu   sync.RWMutex
	raw  *Ring
	dns  *Ring
	http *Ring
	icmp *Ring
}

// NewRingSet creates a new RingSet with specified capacities
func NewRingSet(rawCap, dnsCap, httpCap, icmpCap int) *RingSet {
	return &RingSet{
		raw:  New(rawCap),
		dns:  New(dnsCap),
		http: New(httpCap),
		icmp: New(icmpCap),
	}
}

// GetRaw returns the raw packet ring
func (rs *RingSet) GetRaw() *Ring {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.raw
}

// GetDNS returns the DNS session ring
func (rs *RingSet) GetDNS() *Ring {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.dns
}

// GetHTTP returns the HTTP session ring
func (rs *RingSet) GetHTTP() *Ring {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.http
}

// GetICMP returns the ICMP session ring
func (rs *RingSet) GetICMP() *Ring {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.icmp
}

// ResizeRaw resizes the raw packet ring with smooth migration
func (rs *RingSet) ResizeRaw(newCap int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.raw = rs.raw.Resize(newCap)
}

// ResizeDNS resizes the DNS session ring
func (rs *RingSet) ResizeDNS(newCap int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.dns = rs.dns.Resize(newCap)
}

// ResizeHTTP resizes the HTTP session ring
func (rs *RingSet) ResizeHTTP(newCap int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.http = rs.http.Resize(newCap)
}

// ResizeICMP resizes the ICMP session ring
func (rs *RingSet) ResizeICMP(newCap int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.icmp = rs.icmp.Resize(newCap)
}

// ClearAll clears all ring buffers
func (rs *RingSet) ClearAll() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.raw.Clear()
	rs.dns.Clear()
	rs.http.Clear()
	rs.icmp.Clear()
}

