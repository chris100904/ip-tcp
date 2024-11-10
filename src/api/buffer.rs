pub struct CircularBuffer {
    buffer: Vec<u8>,
    capacity: usize,
    base_seq: u32, 
    start: usize,
    end: usize,
}

impl CircularBuffer {
    pub fn new(capacity: usize) -> Self {
        CircularBuffer {
            buffer: vec![0; capacity],
            capacity, 
            base_seq: 0,
            start: 0,
            end: 0,
        }
    }

    pub fn seq_to_index(&self, seq: u32) -> usize {
        ((seq - self.base_seq) as usize) % self.capacity
    }

    pub fn index_to_seq(&self, index: usize) -> u32 {
        self.base_seq.wrapping_add(index as u32)
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        todo!()
    }

    pub fn read(&mut self, len: usize) -> Vec<u8> {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn is_full(&self) -> bool {
        (self.end + 1) % self.capacity == self.start
    }

    pub fn available_space(&self) -> usize {
        if self.end >= self.start {
            self.capacity - (self.end - self.start)
        } else {
            self.start - self.end - 1
        }
    }
}