use num_complex::Complex64;

/// DMA buffer for I/Q samples with watermark threshold
pub struct DMABuffer {
    /// Backing storage
    data: Vec<Complex64>,
    /// Maximum capacity
    capacity: usize,
    /// Watermark level for DMA trigger
    watermark: usize,
}

impl DMABuffer {
    /// Create a new DMABuffer with the given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
            watermark: capacity / 2,
        }
    }

    /// Set the watermark level
    pub fn set_watermark(&mut self, watermark: usize) {
        self.watermark = watermark.min(self.capacity);
    }

    /// Get the current watermark
    pub fn watermark(&self) -> usize {
        self.watermark
    }

    /// Get the buffer capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return a zero-copy slice of the stored samples
    pub fn zero_copy_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Write samples into the buffer. Returns the number of samples written.
    pub fn write_samples(&mut self, samples: &[Complex64]) -> usize {
        let n = samples.len().min(self.capacity - self.data.len());
        self.data.extend_from_slice(&samples[..n]);
        n
    }

    /// Clear all stored samples
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// Ring buffer with read/write cursors for sample streaming
pub struct RingBuffer {
    /// Backing storage
    data: Vec<Complex64>,
    /// Maximum capacity (must be power of two)
    capacity: usize,
    /// Write cursor (absolute position)
    write_cursor: usize,
    /// Read cursor (absolute position)
    read_cursor: usize,
}

impl RingBuffer {
    /// Create a new RingBuffer with the given capacity (rounded up to power of two)
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two();
        Self {
            data: vec![Complex64::new(0.0, 0.0); cap],
            capacity: cap,
            write_cursor: 0,
            read_cursor: 0,
        }
    }

    /// Return the current number of samples available for reading
    pub fn available(&self) -> usize {
        self.write_cursor - self.read_cursor
    }

    /// Return the remaining write capacity
    pub fn remaining(&self) -> usize {
        self.capacity - self.available()
    }

    /// Write samples into the ring buffer. Returns the number written.
    pub fn write(&mut self, samples: &[Complex64]) -> usize {
        let n = samples.len().min(self.remaining());
        let mask = self.capacity - 1;
        for (i, &sample) in samples[..n].iter().enumerate() {
            let idx = (self.write_cursor + i) & mask;
            self.data[idx] = sample;
        }
        self.write_cursor += n;
        n
    }

    /// Read samples from the ring buffer. Returns the number read.
    pub fn read(&mut self, buffer: &mut [Complex64]) -> usize {
        let n = buffer.len().min(self.available());
        let mask = self.capacity - 1;
        for (i, slot) in buffer[..n].iter_mut().enumerate() {
            let idx = (self.read_cursor + i) & mask;
            *slot = self.data[idx];
        }
        self.read_cursor += n;
        n
    }
}
