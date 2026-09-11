package stream

import "sync"

// chunkPools holds one buffer pool per permitted chunk size. Pooling keeps the
// hot path free of per-chunk allocations, which matters for a proxy serving many
// concurrent streams: memory stays proportional to the number of active streams
// rather than to the number of chunks they move.
var chunkPools = func() [MaxLog2ChunkSize - MinLog2ChunkSize + 1]*sync.Pool {
	var pools [MaxLog2ChunkSize - MinLog2ChunkSize + 1]*sync.Pool
	for i := range pools {
		size := 1<<(uint(i)+MinLog2ChunkSize) + TagSize
		pools[i] = &sync.Pool{New: func() any {
			b := make([]byte, size)
			return &b
		}}
	}
	return pools
}()

// getChunkBuf returns a buffer holding one chunk of plaintext plus its tag.
// log2C must already have been validated.
func getChunkBuf(log2C uint8) *[]byte {
	return chunkPools[log2C-MinLog2ChunkSize].Get().(*[]byte)
}

// putChunkBuf returns a buffer to its pool. Passing nil is a no-op, so callers
// can release unconditionally.
func putChunkBuf(log2C uint8, b *[]byte) {
	if b == nil {
		return
	}
	chunkPools[log2C-MinLog2ChunkSize].Put(b)
}
