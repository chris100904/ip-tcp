use std::net::SocketAddr;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Condvar};

use super::tcp::Socket;

pub struct TcpListener {
  // TODO: add a TcpListener struct to hold the TcpListener object
  // A list of sockets for new/pending connections
  pending_connections: Arc<(Mutex<VecDeque<Socket>>, Condvar)>,
}

impl TcpListener {
  pub fn listen() -> TcpListener {
      TcpListener {
          pending_connections: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
      }
  }

  pub fn accept(&self) -> Socket {
        let (lock, cvar) = &*self.pending_connections;
        let mut connections = lock.lock().unwrap();

        // Wait until a connection is available
        while connections.is_empty() {
            connections = cvar.wait(connections).unwrap();
        }

        // Remove and return the first connection
        let socket = connections.pop_front().unwrap();

        // Create normal socket with this socket connection
  }

  pub fn add_connection(&self, socket: Socket) {
    let (lock, cvar) = &*self.pending_connections;
    let mut connections = lock.lock().unwrap();

    // Add the new connection
    connections.push_back(socket);

    // Notify waiting threads that a new connection is available
    cvar.notify_one();
  }

  pub fn close(&self) -> Result<(), String> {
    // TODO: Implement TCP closing
    unimplemented!();
  }
}

pub struct TcpStream {
  // TODO: add a TcpStream struct to hold the TcpStream object    
  // A buffer for reading data
  read_buffer: Vec<u8>,
    
  // A buffer for writing data
  write_buffer: Vec<u8>,
}

impl TcpStream {
  pub fn connect(addr: SocketAddr) -> Result<TcpStream, String> {
    // TODO: Implement TCP connecting

    // create a new normal socket


    // IN TCP STACK if there is no error, add the info to the socket table
    // TCP STACK will handle creating the actual socket struct, but this function returns the TcpStream itself, which is just part of the struct
    // otherwise, print out an error
    unimplemented!();   
  }

  pub fn read(&self, buf: &mut[u8]) -> Result<usize, String> {
      // TODO: Implement TCP reading
      unimplemented!();
  }

  pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
      // TODO: Implement TCP writing
      unimplemented!();
  }   

  pub fn close(&self) -> Result<(), String> {
      // TODO: Implement TCP closing
      unimplemented!();
  }
}