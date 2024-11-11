pub const BUFFER_SIZE: usize = 65536;

#[derive(Clone, Debug)]
pub struct CircularBuffer {
    buffer: Vec<u8>,
    capacity: usize,
    base_seq: u32, 
    start: usize,
    end: usize,
}

impl CircularBuffer {
    pub fn new() -> Self {
        CircularBuffer {
            buffer: vec![0; BUFFER_SIZE],
            capacity: BUFFER_SIZE, 
            base_seq: 0,
            start: 0,
            end: 0,
        }
    }

    pub fn clone(&self) -> CircularBuffer {
      CircularBuffer {
        buffer: self.buffer.clone(),
        capacity: self.capacity,
        base_seq: self.base_seq,
        start: self.start,
        end: self.end,
      }
    }

    pub fn seq_to_index(&self, seq: u32) -> usize {
        ((seq - self.base_seq) as usize) % self.capacity
    }

    pub fn index_to_seq(&self, index: usize) -> u32 {
        self.base_seq.wrapping_add(index as u32)
    }

    // Write data to the circular buffer.
    //
    // Returns the number of bytes written to the buffer. If the buffer is full,
    // this function will return early and not write all of the provided data.
    //
    pub fn write(&mut self, data: &[u8]) -> usize {
        let mut bytes_written = 0;
        for &byte in data {
            if self.is_full() {
                break;
            }
            self.buffer[self.end] = byte;
            self.end = (self.end + 1) % self.capacity;
            bytes_written += 1;
        }
        bytes_written
    }

    // Returns all of the bytes in the circular buffer and clears the buffer.
    //
    // This method is useful for reading all of the data from the buffer at once.
    pub fn read_all(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        while !self.is_empty() {
            data.push(self.buffer[self.start]);
            self.start = (self.start + 1) % self.capacity;
        }
        data
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