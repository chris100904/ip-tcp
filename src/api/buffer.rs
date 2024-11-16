// use std::sync::{Arc, Condvar, Mutex};

// use super::tcp::SocketStatus;

pub const BUFFER_SIZE: usize = 65536;



#[derive(Clone, Debug)]
pub struct SendBuffer {
  pub buffer: CircularBuffer,
  // pointers refer to sequence numbers, not buffer indices
  pub una: u32,
  pub nxt: u32,
  pub lbw: u32, 
}

impl SendBuffer {
  pub fn new() -> SendBuffer {
    SendBuffer {
      buffer: CircularBuffer::new(),
      una: 0,
      nxt: 0,
      lbw: 0,
    }
  }

  pub fn clone(&self) -> SendBuffer {
    SendBuffer { 
      buffer: self.buffer.clone(), 
      una: self.una, 
      nxt: self.nxt, 
      lbw: self.lbw,
    }
  }

  // Write data to the send buffer.
  // Returns the number of bytes written. If the buffer is full, returns 0.
  pub fn write(&mut self, data: &[u8]) -> usize {
    // take amount of bytes written in buffer and subtract by total capacity
    let available_space = BUFFER_SIZE.wrapping_sub(self.lbw.wrapping_sub(self.una) as usize);
    
    // need to only be able to write as much as we can (can't overfill the buffer) 
    let bytes_to_write = std::cmp::min(data.len(), available_space); 

    let bytes_written = self.buffer.write(self.lbw, &data[..bytes_to_write]);
    self.lbw = self.lbw.wrapping_add(bytes_written as u32); 
    println!("lbw: {}, nxt: {}", self.lbw, self.nxt);
    bytes_written
  }

  // Update the send buffer's `una` to `new_una` if `new_una` is greater than the current `una`.
  // This is used to acknowledge packets that have been received by the other side.
  pub fn acknowledge(&mut self, new_una: u32) { 
    if new_una > self.una {
        self.una = new_una;
        self.buffer.update_base_seq(new_una);
    }
  }
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
  
  // Write data into the receive buffer.
  // Returns the number of bytes written. If no space is available, returns 0.
  pub fn write(&mut self, data_seq: u32, data: &[u8]) -> usize {
    let available_space = self.wnd.wrapping_sub(self.nxt.wrapping_sub(self.lbr) as u16) as usize;
    let bytes_to_write = std::cmp::min(data.len(), available_space);

    if bytes_to_write == 0{
        return 0; // no space available, cannot write anything 
    }

    let bytes_written = self.buffer.write(data_seq, &data[..bytes_to_write]);

    // Update nxt to reflect the last byte received 
    self.nxt = data_seq.wrapping_add(bytes_written as u32);

    bytes_written
  }

  // Advance the left boundary of the receive buffer by `bytes_read` bytes. Used when reading
  pub fn consume(&mut self, bytes_read: u32) {
    self.lbr = self.lbr.wrapping_add(bytes_read);
    self.buffer.update_base_seq(self.lbr);
  }
}

#[derive(Clone, Debug)]
pub struct CircularBuffer {
    pub buffer: Vec<u8>,
    capacity: usize,
    base_seq: u32, // base sequence number for the first byte in the buffer that has been written into
}

impl CircularBuffer {
    pub fn new() -> Self {
        CircularBuffer {
            buffer: vec![0; BUFFER_SIZE],
            capacity: BUFFER_SIZE, 
            base_seq: 0,
        }
    }

    pub fn clone(&self) -> CircularBuffer {
      CircularBuffer {
        buffer: self.buffer.clone(),
        capacity: self.capacity,
        base_seq: self.base_seq,
      }
    }

    pub fn seq_to_index(&self, seq: u32) -> usize {
        ((seq.wrapping_sub(self.base_seq)) as usize) % self.capacity
    }

    // Writes data to the circular buffer starting at the given sequence number.
    // Returns the number of bytes successfully written.
    pub fn write(&mut self, seq: u32, data: &[u8]) -> usize {
        let mut bytes_written = 0;
        let mut current_seq = seq;

        for &byte in data {
            if self.available_space() == 0 {
                break; 
            }
            let index = self.seq_to_index(current_seq);
            self.buffer[index] = byte;

            current_seq = current_seq.wrapping_add(1);
            bytes_written += 1
        }
        println!("{:?}", self.buffer[self.seq_to_index(current_seq) - 1 as usize]);
        bytes_written 
    }
    

    // Returns all of the bytes in the circular buffer and clears the buffer.
    // This method is useful for reading all of the data from the buffer at once.
    pub fn read_all(&mut self, lbr: u32, nxt: u32) -> Vec<u8> {
        let mut data = Vec::new();
        let mut current = lbr;

        while nxt.wrapping_sub(current) > 0 {
            let index = self.seq_to_index(current);
            data.push(self.buffer[index]);
            current = current.wrapping_add(1); 
        }
        data
    }

    // Returns the bytes in the circular buffer that we want to read starting from lbr to lrb + len
    pub fn read(&mut self, lbr: u32, len: u32) -> Vec<u8> {
        let mut data = Vec::new();
        let mut current_seq = lbr;

        for _ in 0..len {
            let index = self.seq_to_index(current_seq);
            data.push(self.buffer[index]);
            current_seq = current_seq.wrapping_add(1);
        }

        data
    }

    pub fn update_base_seq(&mut self, new_base_seq: u32) {
        self.base_seq = new_base_seq;
    }

    pub fn available_space(&self) -> usize {
        BUFFER_SIZE - (self.base_seq.wrapping_sub(self.base_seq) as usize)
    }
}