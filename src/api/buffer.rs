use std::sync::{Arc, Condvar, Mutex};

use super::tcp::SocketStatus;

pub const BUFFER_SIZE: usize = 65536;



#[derive(Clone, Debug)]
pub struct SendBuffer {
  pub buffer: CircularBuffer,
  // pointers refer to sequence numbers, not buffer indices
  pub una: u32,
  pub nxt: u32,
  pub lbw: u32, 
  // pub wnd: u16,
}

impl SendBuffer {
  pub fn new() -> SendBuffer {
    SendBuffer {
      buffer: CircularBuffer::new(),
      una: 0,
      nxt: 0,
      lbw: 0,
      // wnd: 0,
    }
  }

  pub fn clone(&self) -> SendBuffer {
    SendBuffer { 
      buffer: self.buffer.clone(), 
      una: self.una, 
      nxt: self.nxt, 
      lbw: self.lbw,
      // wnd: self.wnd
    }
  }

  pub fn write(&mut self, data: &[u8]) -> usize {
      let available_space = BUFFER_SIZE - (self.nxt.wrapping_sub(self.una) as usize);
      let bytes_to_write = std::cmp::min(data.len(), available_space);
      
      let bytes_written = self.buffer.write(self.lbw, &data[..bytes_to_write]);
      self.lbw = self.lbw.wrapping_add(bytes_written as u32);
      
      bytes_written
  }

  // pub fn is_full(&self) -> bool {
  //   (self.nxt - self.una) as usize >= self.wnd as usize
  // }
}

#[derive(Clone, Debug)]
pub struct ReceiveBuffer {
  pub buffer: CircularBuffer,
  // pointers refer to sequence numbers, not buffer indices
  pub nxt: u32,
  pub wnd: u16,
  pub lbr: u32,
}

impl ReceiveBuffer {
  pub fn new() -> ReceiveBuffer {
    ReceiveBuffer {
      buffer: CircularBuffer::new(),
      nxt: 0,
      wnd: 65535, 
      lbr: 0,
    }
  }

  pub fn clone(&self) -> ReceiveBuffer {
    ReceiveBuffer { 
      buffer: self.buffer.clone(), 
      nxt: self.nxt,
      wnd: self.wnd,
      lbr: self.lbr,
    }
  }

  // pub fn has_space(&self) -> bool {
  //     (self.nxt - self.lbr) as usize < self.wnd as usize
  // }
}

#[derive(Clone, Debug)]
pub struct CircularBuffer {
    pub buffer: Vec<u8>,
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
    // Returns the last index that we stopped at. If the buffer is full,
    // this function will return early and not write all of the provided data.
    //
    

    // Returns all of the bytes in the circular buffer and clears the buffer.
    //
    // This method is useful for reading all of the data from the buffer at once.
    pub fn read_all(&mut self, lbr: u32, nxt: u32) -> Vec<u8> {
        let mut data = Vec::new();
        
        // if there's no data to read, return an empty Vec
        if lbr == nxt {
            return data;
        }
        let mut current = lbr;
        // loop to read data, handling sequence wrapping
        while nxt.wrapping_sub(current) > 0 {
            let index = self.seq_to_index(lbr);
            data.push(self.buffer[index]);
            current = current.wrapping_add(1);
        }
        data
    }

    // Returns the bytes in the circular buffer that we want to read starting from lbr to lrb + len
    pub fn read(&mut self, lbr: &u32, len: &u32) -> Vec<u8> {
        let mut data = Vec::new();

        let mut current_seq = *lbr;

        for _ in 0..*len {
          let index = self.seq_to_index(current_seq);
          data.push(self.buffer[index]);
          current_seq = current_seq.wrapping_add(1);
        }

        data
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