use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct BufferPool {
    chunk_size: usize,
    max_cached: usize,
    cached: VecDeque<Vec<u8>>,
}

impl BufferPool {
    pub fn new(chunk_size: usize, max_cached: usize) -> Self {
        Self {
            chunk_size,
            max_cached,
            cached: VecDeque::new(),
        }
    }

    pub fn acquire(&mut self) -> Vec<u8> {
        self.cached
            .pop_front()
            .unwrap_or_else(|| Vec::with_capacity(self.chunk_size))
    }

    pub fn release(&mut self, mut buffer: Vec<u8>) {
        if self.cached.len() >= self.max_cached
            || buffer.capacity() < self.chunk_size
            || buffer.capacity() > self.chunk_size.saturating_mul(2)
        {
            return;
        }
        buffer.clear();
        self.cached.push_back(buffer);
    }

    pub fn cached(&self) -> usize {
        self.cached.len()
    }

    pub fn cached_bytes(&self) -> usize {
        self.cached.iter().map(|buffer| buffer.capacity()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::BufferPool;

    #[test]
    fn reuses_buffers_up_to_the_cache_limit() {
        let mut pool = BufferPool::new(128, 2);
        let first = pool.acquire();
        let first_capacity = first.capacity();
        pool.release(first);

        assert_eq!(pool.cached(), 1);
        assert_eq!(pool.cached_bytes(), first_capacity);
        assert!(pool.acquire().capacity() >= 128);

        pool.release(Vec::with_capacity(128));
        pool.release(Vec::with_capacity(128));
        pool.release(Vec::with_capacity(128));
        assert_eq!(pool.cached(), 2);
        assert_eq!(pool.cached_bytes(), 256);
    }

    #[test]
    fn rejects_undersized_and_oversized_allocations() {
        let mut pool = BufferPool::new(128, 2);
        pool.release(Vec::with_capacity(64));
        pool.release(Vec::with_capacity(257));

        assert_eq!(pool.cached(), 0);
        assert_eq!(pool.cached_bytes(), 0);
    }
}
