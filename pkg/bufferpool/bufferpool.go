// Package bufferpool provides a globally accessible, tiered buffer pool.
// It allocates and reuses buffers from predefined size tiers to reduce memory
// allocations in applications that frequently create and discard buffers.
package bufferpool

import (
	"sync"
)

// tierSizes defines the set of buffer sizes managed by the tiered buffer pool.
// These tiers are selected to cover a range of typical usage patterns.
//
// Adjusting these tiers may help optimize performance for certain workloads.
// Tiers must be strictly ascending in size.
var tierSizes = []int{
	256,      // Useful for small metadata or very small reads/writes
	1 << 10,  // 1KB
	4 << 10,  // 4KB
	16 << 10, // 16KB
	32 << 10, // 32KB
	64 << 10, // 64KB: largest expected buffer size
}

// sizedBufferPool is a pool dedicated to one fixed buffer size.
// It uses a sync.Pool to store and reuse buffers of that size.
type sizedBufferPool struct {
	defaultSize int
	pool        sync.Pool
}

// newSizedBufferPool creates a pool of buffers with a fixed defaultSize.
func newSizedBufferPool(size int) *sizedBufferPool {
	return &sizedBufferPool{
		defaultSize: size,
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

// get retrieves a buffer of at least the requested length from this pool.
// If length is smaller than defaultSize, it slices down the returned buffer.
func (p *sizedBufferPool) get(length int) *[]byte {
	buf := p.pool.Get().(*[]byte)
	if length < p.defaultSize {
		*buf = (*buf)[:length]
	} else {
		*buf = (*buf)[:p.defaultSize]
	}
	return buf
}

// put returns a buffer to the pool. It resets the buffer length to full capacity
// to standardize what subsequent callers receive.
func (p *sizedBufferPool) put(buf *[]byte) {
	if cap(*buf) != p.defaultSize {
		// Should not happen if used correctly, but we handle it gracefully.
		newBuf := make([]byte, p.defaultSize)
		p.pool.Put(&newBuf)
		return
	}
	*buf = (*buf)[:p.defaultSize]
	p.pool.Put(buf)
}

// tieredBufferPool uses multiple sizedBufferPools for different buffer sizes.
// Requests are matched to the smallest tier that can fulfill the request.
type tieredBufferPool struct{ sizedPools []*sizedBufferPool }

// get selects the appropriate pool based on requested size.
func (p *tieredBufferPool) get(length int) *[]byte {
	switch {
	case length <= 256:
		return p.sizedPools[0].get(length)
	case length <= 1<<10:
		return p.sizedPools[1].get(length)
	case length <= 4<<10:
		return p.sizedPools[2].get(length)
	case length <= 16<<10:
		return p.sizedPools[3].get(length)
	case length <= 32<<10:
		return p.sizedPools[4].get(length)
	default:
		return p.sizedPools[5].get(length)
	}
}

// put returns a buffer to the appropriate pool based on its capacity.
func (p *tieredBufferPool) put(buf *[]byte) {
	capacity := cap(*buf)
	switch {
	case capacity == 256:
		p.sizedPools[0].put(buf)
	case capacity == 1<<10:
		p.sizedPools[1].put(buf)
	case capacity == 4<<10:
		p.sizedPools[2].put(buf)
	case capacity == 16<<10:
		p.sizedPools[3].put(buf)
	case capacity == 32<<10:
		p.sizedPools[4].put(buf)
	case capacity == 64<<10:
		p.sizedPools[5].put(buf)
	default:
		// This shouldn't happen if used correctly....
		// For safety, we’ll just discard it.
	}
}

var globalPool tieredBufferPool

func init() {
	globalPool.sizedPools = make([]*sizedBufferPool, len(tierSizes))
	for i, s := range tierSizes {
		globalPool.sizedPools[i] = newSizedBufferPool(s)
	}
}

// GetBuffer returns a buffer of at least the requested length.
// The returned buffer is owned by the caller until returned via ReturnBuffer.
func GetBuffer(length int) *[]byte { return globalPool.get(length) }

// ReturnBuffer returns a buffer obtained from GetBuffer back to the pool.
// After calling ReturnBuffer, the buffer must not be used.
func ReturnBuffer(buf *[]byte) { globalPool.put(buf) }
