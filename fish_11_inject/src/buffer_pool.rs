//! Buffer pool for efficient memory management in FiSH_11
//!
//! This module provides a thread-safe buffer pool to reduce memory allocations
//! and improve performance for socket data processing.

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use log::{debug, trace};
use parking_lot::Mutex;

/// Maximum buffer size to keep in the pool (in bytes)
const MAX_POOL_BUFFER_SIZE: usize = 16 * 1024; // 16KB

/// Maximum number of buffers to keep in the pool
const MAX_POOLED_BUFFERS: usize = 64;

/// BufferPool provides efficient buffer management for socket operations
#[derive(Debug)]
pub struct BufferPool {
    pool: Mutex<VecDeque<BytesMut>>,
    stats: Mutex<BufferPoolStats>,
}

/// Statistics about buffer pool usage
#[derive(Debug, Clone, Default)]
pub struct BufferPoolStats {
    pub allocations: usize,
    pub reuses: usize,
    pub current_pool_size: usize,
    pub max_pool_size: usize,
}

impl BufferPool {
    /// Create a new BufferPool
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pool: Mutex::new(VecDeque::with_capacity(MAX_POOLED_BUFFERS)),
            stats: Mutex::new(BufferPoolStats::default()),
        })
    }

    /// Acquire a buffer with at least the specified capacity
    ///
    /// This will either reuse a pooled buffer or allocate a new one.
    ///
    /// # Arguments
    /// * `min_capacity` - Minimum required capacity for the buffer
    ///
    /// # Returns
    /// A BytesMut buffer with at least the requested capacity
    pub fn acquire(&self, min_capacity: usize) -> BytesMut {
        let mut stats = self.stats.lock();
        stats.allocations += 1;

        // Try to find a suitable buffer in the pool
        if let Some(buffer) = self.try_acquire_from_pool(min_capacity) {
            stats.reuses += 1;
            debug!(
                "BufferPool: reused buffer (capacity: {}, requested: {})",
                buffer.capacity(),
                min_capacity
            );
            return buffer;
        }

        // No suitable buffer found, allocate a new one
        let capacity = std::cmp::max(min_capacity, 1024); // Minimum 1KB
        let buffer = BytesMut::with_capacity(capacity);

        trace!(
            "BufferPool: allocated new buffer (capacity: {}, requested: {})",
            buffer.capacity(),
            min_capacity
        );

        buffer
    }

    /// Try to acquire a buffer from the pool
    fn try_acquire_from_pool(&self, min_capacity: usize) -> Option<BytesMut> {
        let mut pool = self.pool.lock();

        // Find the first buffer that meets our capacity requirements
        if let Some(index) = pool.iter().position(|buf| buf.capacity() >= min_capacity) {
            let mut stats = self.stats.lock();
            stats.current_pool_size -= 1;
            Some(pool.remove(index).unwrap())
        } else {
            None
        }
    }

    /// Release a buffer back to the pool
    ///
    /// Buffers are cleared and returned to the pool for reuse.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to release back to the pool
    pub fn release(&self, mut buffer: BytesMut) {
        // Only pool buffers that meet our size criteria
        if buffer.capacity() > MAX_POOL_BUFFER_SIZE {
            trace!("BufferPool: not pooling large buffer (capacity: {})", buffer.capacity());
            return;
        }

        // Clear the buffer before pooling
        buffer.clear();

        let mut pool = self.pool.lock();
        let mut stats = self.stats.lock();

        // If pool is full, don't add more buffers
        if pool.len() >= MAX_POOLED_BUFFERS {
            trace!(
                "BufferPool: pool full ({}/{}), dropping buffer",
                pool.len(),
                MAX_POOLED_BUFFERS
            );
            return;
        }

        pool.push_back(buffer);
        stats.current_pool_size += 1;
        stats.max_pool_size = stats.max_pool_size.max(pool.len());

        trace!(
            "BufferPool: returned buffer to pool (pool size: {}/{})",
            pool.len(),
            MAX_POOLED_BUFFERS
        );
    }

    /// Get statistics about the buffer pool
    pub fn get_stats(&self) -> BufferPoolStats {
        self.stats.lock().clone()
    }

    /// Clear the buffer pool (useful for testing or cleanup)
    pub fn clear(&self) {
        let mut pool = self.pool.lock();
        pool.clear();

        let mut stats = self.stats.lock();
        stats.current_pool_size = 0;

        debug!("BufferPool: cleared all pooled buffers");
    }
}

// Note: BufferPool doesn't implement Default because it returns Arc<Self>
// Users should use BufferPool::new() directly

/// SmartBuffer wraps a BytesMut with automatic pool management
#[derive(Debug)]
pub struct SmartBuffer {
    buffer: BytesMut,
    pool: Arc<BufferPool>,
}

impl SmartBuffer {
    /// Create a new SmartBuffer from the pool
    pub fn new(pool: Arc<BufferPool>, min_capacity: usize) -> Self {
        Self { buffer: pool.acquire(min_capacity), pool }
    }

    /// Get the underlying BytesMut for direct manipulation
    pub fn as_bytes_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    /// Convert to Bytes (immutable)
    /// Note: This consumes the SmartBuffer and the underlying buffer
    /// is NOT returned to the pool since frozen buffers are meant to be shared
    pub fn into_bytes(mut self) -> Bytes {
        // Take ownership of the buffer by replacing it with an empty one
        let buffer = std::mem::take(&mut self.buffer);
        buffer.freeze()
    }

    /// Get the current length of the buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Get the current capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Clear the buffer (but keep the allocated capacity)
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Drop for SmartBuffer {
    fn drop(&mut self) {
        // Take ownership of the buffer without cloning, then release it to the pool.
        // Using clone() here would create a duplicate : the original would be dropped
        // normally while the clone is returned to the pool, wasting memory.
        let buffer = std::mem::take(&mut self.buffer);
        if !buffer.is_empty() || buffer.capacity() > 0 {
            self.pool.release(buffer);
        }
    }
}

impl std::ops::Deref for SmartBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl std::ops::DerefMut for SmartBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic() {
        let pool = BufferPool::new();

        // Acquire a buffer
        let buffer1 = pool.acquire(1024);
        assert!(buffer1.capacity() >= 1024);

        // Release it back
        pool.release(buffer1);

        // Acquire again (should reuse)
        let buffer2 = pool.acquire(512);
        assert!(buffer2.capacity() >= 512);

        let stats = pool.get_stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.reuses, 1);
    }

    #[test]
    fn test_smart_buffer() {
        let pool = BufferPool::new();

        {
            let mut smart_buf = SmartBuffer::new(pool.clone(), 2048);
            smart_buf.extend_from_slice(b"test data");
            assert_eq!(smart_buf.len(), 9);
            // Buffer automatically returned to pool when dropped
        }

        let stats = pool.get_stats();
        assert!(stats.reuses > 0 || stats.allocations > 0);
    }

    #[test]
    fn test_pool_limits() {
        let pool = BufferPool::new();

        // Fill the pool
        for _ in 0..MAX_POOLED_BUFFERS + 10 {
            let buffer = pool.acquire(100);
            pool.release(buffer);
        }

        let stats = pool.get_stats();
        assert!(stats.max_pool_size <= MAX_POOLED_BUFFERS);
    }
}
