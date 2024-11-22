// use std::sync::{Arc, Condvar, Mutex};

// use super::tcp::SocketStatus;

use std::collections::BTreeMap;

pub const BUFFER_SIZE: usize = 7; // 65535

#[derive(Clone, Debug)]
pub struct SendBuffer {
  pub buffer: CircularBuffer,
  // pointers refer to sequence numbers, not buffer indices
  pub una: u32,
  pub nxt: u32,
  pub lbw: u32, 
  pub prev_lbw: u32, // represents previous lbw value
}

impl SendBuffer {
  pub fn new() -> SendBuffer {
    SendBuffer {
      buffer: CircularBuffer::new(),
      una: 0,
      nxt: 0,
      lbw: 0,
      prev_lbw: 0,
    }
  }

  pub fn clone(&self) -> SendBuffer {
    SendBuffer { 
      buffer: self.buffer.clone(), 
      una: self.una, 
      nxt: self.nxt, 
      lbw: self.lbw,
      prev_lbw: self.prev_lbw,
    }
  }

  // Write data to the send buffer.
  // Returns the number of bytes written. If the buffer is full, returns 0.
  pub fn write(&mut self, data: &[u8]) -> usize {
    // println!("before write lbw: {}, nxt: {}, una: {}, prev_lbw: {}", self.lbw, self.nxt, self.una, self.prev_lbw);
    // take amount of bytes written in buffer and subtract by total capacity
    let available_space = BUFFER_SIZE.wrapping_sub(self.lbw.wrapping_sub(self.una) as usize);
    
    // need to only be able to write as much as we can (can't overfill the buffer) 
    let bytes_to_write = std::cmp::min(data.len(), available_space); 

    // use lbw + 1 because we want to start at the next one, lbw currently points to somewhere that was already written
    let bytes_written = self.buffer.write(self.lbw + 1, &data[..bytes_to_write]);
    // // temp fix to off by 1 issue
    // if self.lbw == 0 {
    //   bytes_written -= 1;
    // }
    // should lbw be set here?
    self.prev_lbw = self.lbw;
    self.lbw = self.lbw.wrapping_add(bytes_written as u32); 
    // println!("after lbw: {}, nxt: {}, una: {}, prev_lbw: {}", self.lbw, self.nxt, self.una, self.prev_lbw);
    bytes_written
  }

  // Update the send buffer's `una` to `new_una` if `new_una` is greater than the current `una`.
  // This is used to acknowledge packets that have been received by the other side.
  pub fn acknowledge(&mut self, new_una: u32) { 
    if new_una > self.una {
        self.una = new_una;
        // self.buffer.update_base_seq(new_una);
    }
  }

  pub fn is_empty(&self) -> bool {
    self.lbw == self.una
  }
}

#[derive(Clone, Debug)]
pub struct ReceiveBuffer {
  pub buffer: CircularBuffer,
  // pointers refer to sequence numbers, not buffer indices
  pub nxt: u32,
  pub wnd: u16,
  pub lbr: u32,
  pub out_of_order: BTreeMap<u32, Vec<u8>>,
}

impl ReceiveBuffer {
  pub fn new() -> ReceiveBuffer {
    ReceiveBuffer {
      buffer: CircularBuffer::new(),
      nxt: 0,
      wnd: BUFFER_SIZE.try_into().unwrap(), 
      lbr: 0,
      out_of_order: BTreeMap::new(),
    }
  }

  pub fn clone(&self) -> ReceiveBuffer {
    ReceiveBuffer { 
      buffer: self.buffer.clone(), 
      nxt: self.nxt,
      wnd: self.wnd,
      lbr: self.lbr,
      out_of_order: self.out_of_order.clone()
    }
  }
  
  // Write data into the receive buffer.
  // Returns the number of bytes written. If no space is available, returns 0.
  pub fn write(&mut self, data_seq: u32, data: &[u8]) -> usize {
    // let available_space = self.wnd.wrapping_sub(self.nxt.wrapping_sub(self.lbr) as u16) as usize;
    let available_space = self.wnd as usize;
    // println!("AVAILABLE SPACE: {} = WINDOW: {} - (NXT: {} - LBR: {})", available_space, self.wnd, self.nxt, self.lbr); 
    let bytes_to_write = std::cmp::min(data.len(), available_space);

    if bytes_to_write == 0 {
        return 0; // no space available, cannot write anything 
    }
    // println!("BEFORE lbr: {}, nxt: {}, data_seq: {}", self.lbr, self.nxt, data_seq);
    

    if data_seq == self.nxt {
        // In-order packet handling
        // println!("IN ORDER PACKET HANDLED HERE");
        let bytes_written = self.buffer.write(data_seq, &data[..bytes_to_write]);

        // Update nxt to reflect the last byte received 
        self.nxt = data_seq.wrapping_add(bytes_written as u32);

        // in the case that a gap has been filled, we call process_out_of_order in order to check
        self.process_out_of_order();
        // println!("AFTER lbr: {}, nxt: {}, data_seq: {}", self.lbr, self.nxt, data_seq);
        // println!("Buffer after write: {:?}", self.buffer.read(self.lbr + 1, self.nxt.wrapping_sub(self.lbr + 1)));

        // Update window size
        // println!("PREV WND: {}", self.wnd);
        println!("BUFFER_SIZE: {} - (NXT: {} - (LBR: {} + 1))", BUFFER_SIZE, self.nxt, self.lbr);
        self.wnd = (BUFFER_SIZE - (self.nxt.wrapping_sub(self.lbr.wrapping_add(1)) as usize)) as u16;
        // println!("WND: {} = BUFFER_SIZE: {} - (NXT: {} - (LBR: {} + 1))", self.wnd, BUFFER_SIZE, self.nxt, self.lbr);
        // println!("POST WND: {}", self.wnd);
        bytes_written
    } else if data_seq > self.nxt /* && data_seq < self.nxt.wrapping_add(self.wnd as u32) */{
        // println!("OUT OF ORDER PACKET");
        // Out-of-order packet within the receive window
        self.out_of_order.insert(data_seq, data[..bytes_to_write].to_vec());
        self.process_out_of_order();
        bytes_to_write
    } else {
      // println!("BAH");
        // Packet outside the receive window, ignore (or whatever protocol we want to use)
        0
    }
  }

  // Check if there is a packet from the BTreeMap and write it into the buffer
  fn process_out_of_order(&mut self) {
    while let Some((&seq, data)) = self.out_of_order.first_key_value() {
        if seq == self.nxt {
            let bytes_written = self.buffer.write(seq, data);
            self.nxt = self.nxt.wrapping_add(bytes_written as u32);
  
            self.out_of_order.remove(&seq);
        } else {
          break;
        }
    }
  }

  // Advance the left boundary of the receive buffer by `bytes_read` bytes. Used when reading
  pub fn consume(&mut self, bytes_read: u32) {
    // println!("BEFORE CONSUME LBR: {}, BYTES_READ: {}", self.lbr, bytes_read);
    self.lbr = self.lbr.wrapping_add(bytes_read);
    // println!("AFTER CONSUME LBR: {}, BYTES_READ: {}", self.lbr, bytes_read);

    // Update window size
    self.wnd = (BUFFER_SIZE - (self.nxt.wrapping_sub(self.lbr.wrapping_add(1)) as usize)) as u16;
  }
}

#[derive(Clone, Debug)]
pub struct CircularBuffer {
    pub buffer: Vec<u8>,
    pub capacity: usize,
}

impl CircularBuffer {
    pub fn new() -> Self {
        CircularBuffer {
            buffer: vec![0; BUFFER_SIZE],
            capacity: BUFFER_SIZE, 
        }
    }

    pub fn clone(&self) -> CircularBuffer {
      CircularBuffer {
        buffer: self.buffer.clone(),
        capacity: self.capacity,
      }
    }

    pub fn seq_to_index(&self, seq: u32) -> usize {
        (seq as usize) % self.capacity
    }

    // Writes data to the circular buffer starting at the given sequence number.
    // Returns the number of bytes successfully written.
    pub fn write(&mut self, seq: u32, data: &[u8]) -> usize {
        let mut bytes_written = 0;
        let mut current_seq = seq;

        for &byte in data {
          // in both send and receive, this is already being checked
          // BUT IF THERE IS A PROBLEM WITH OVERFLOW, CHECK HERE FIRST
            // if self.available_space() == 0 {
            //     println!("IT IS BREAKING?????");
            //     break; 
            // }
            let index = self.seq_to_index(current_seq);
            self.buffer[index] = byte;
            current_seq = current_seq.wrapping_add(1);
            bytes_written += 1
        }
        println!("Wrote bytes: {}", String::from_utf8_lossy(data));
        // println!("NOT WRITTEN circ_buf: current_seq: {}", current_seq);
        // println!("{:?}", self.buffer[self.seq_to_index(current_seq) - 1 as usize]);
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
        // println!("len: {}", len);
        for _ in 0..len {
            let index = self.seq_to_index(current_seq);
            data.push(self.buffer[index]);
            // println!("read: current_seq: {}", current_seq);
            current_seq = current_seq.wrapping_add(1);
        }
        data
    }

    // pub fn available_space(&self, start_point: u32, end_point: u32) -> usize {
    //     BUFFER_SIZE - (end_point.wrapping_sub(start_point) as usize)
    // }
}