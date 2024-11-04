use std::net::{Ipv4Addr, SocketAddr};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, Condvar};

use crate::api::packet::{TcpFlags, TcpPacket};
use crate::api::tcp::{SocketKey, SocketStatus, TcpSocket};

use super::tcp::{Socket, Tcp};

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct Connection {
  pub socket_key: SocketKey,
  pub seq_num: u32,
  pub ack_num: u32
}

impl Connection {
  pub fn clone(&self) -> Connection {
    Connection {
      socket_key: self.socket_key.clone(),
      seq_num: self.seq_num.clone(),
      ack_num: self.ack_num.clone()
    }
  }
}

#[derive(Clone)]
pub struct TcpListener {
  // TODO: add a TcpListener struct to hold the TcpListener object (???)
  // A list of sockets for new/pending connections

  // This may not need to have Arc Mutex because it is being wrapped in the socket table.
  pub incoming_connections: Arc<(Mutex<VecDeque<Connection>>, Condvar)>
}

impl TcpListener {
  pub fn clone(&self) -> TcpListener {
    TcpListener { 
      incoming_connections: Arc::clone(&self.incoming_connections)
    }
  }

  pub fn listen() -> TcpListener {
      TcpListener {
        incoming_connections: Arc::new((Mutex::new(VecDeque::new()), Condvar::new()))
      }
  }

  pub fn accept(&self, tcp: &Tcp) -> Socket {
    let (lock, cvar) = &*self.incoming_connections;
    let connection;
    {
      let mut incoming_conns = lock.lock().unwrap();

      // Wait until a connection is available
      while incoming_conns.is_empty() {
        incoming_conns = cvar.wait(incoming_conns).unwrap();
      }
      // Remove and return the first connection
      connection = incoming_conns.pop_front().unwrap();
    }
    
    // Create normal socket with this socket connection
    let socket = Socket {
      socket_id: tcp.next_unique_id(),
      status: SocketStatus::SynReceived,
      tcp_socket: TcpSocket::Stream(TcpStream::new(SocketStatus::SynReceived, connection.seq_num, connection.ack_num + 1))
    };

    // Send SYN + ACK packet
    let syn_ack_packet = TcpPacket::new_syn_ack(connection.socket_key.local_port.unwrap(), 
      connection.socket_key.remote_port.unwrap(), connection.seq_num, 
      connection.ack_num + 1);
    tcp.send_packet(syn_ack_packet, connection.socket_key.remote_ip.unwrap());
    loop {
      // Update socket table
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        socket_table.insert(connection.socket_key.clone(), socket);
        break;
      }
    }

    let mut status_cv = Arc::new((Mutex::new((SocketStatus::Closed, 0, 0)), Condvar::new()));
    loop {
      // Get current status
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&connection.socket_key).unwrap().tcp_socket{
          status_cv = Arc::clone(&stream.status);
        }
        break;
      }
    }
    {
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();

      // Wait to receive the ACK response
      while *pending_conns != (SocketStatus::Established, connection.seq_num + 1, connection.ack_num + 1) {
        pending_conns = pend_cvar.wait(pending_conns).unwrap();
      }
    }

    loop {
      // Update socket table
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        socket_table.get_mut(&connection.socket_key).unwrap().status = SocketStatus::Established;
        return socket_table.get(&connection.socket_key).unwrap().clone();
      }
    }
  }

  pub fn add_connection(&self, connection: Connection) {
    let (lock, cvar) = &*self.incoming_connections;
    let mut connections = lock.lock().unwrap();

    // Add the new connection
    connections.push_back(connection);

    // Notify waiting threads that a new connection is available
    cvar.notify_all(); // changed one to all
  }

  pub fn close(&self) -> Result<(), String> {
    // TODO: Implement TCP closing
    unimplemented!();
  }
}

#[derive(Clone)]
pub struct TcpStream {
  // May not need to be arc mutexed.
  // Represents SocketStatus, seq_num, ack_num
  pub status: Arc<(Mutex<(SocketStatus, u32, u32)>, Condvar)>,
  // TODO: add a TcpStream struct to hold the TcpStream object    
  // A buffer for reading data
  pub read_buffer: Vec<u8>,
    
  // A buffer for writing data
  pub write_buffer: Vec<u8>,
  // Initial sequence number
  // buffer pointers
  // In the sending case, you might consider keeping track of what packets 
  // you've sent and the timings for those in order to support retransmission 
  // later on, and in the receiving case, you'll need to handle receiving packets out of order.
}

impl TcpStream {
  pub fn new(status: SocketStatus, seq_num: u32, ack_num: u32) -> TcpStream {
    TcpStream { 
      status: Arc::new((Mutex::new((status, seq_num, ack_num)), Condvar::new())),
      read_buffer: Vec::new(), 
      write_buffer: Vec::new() 
    }
  }

  pub fn clone(&self) -> TcpStream {
    TcpStream { 
      status: Arc::clone(&self.status),
      read_buffer: self.read_buffer.clone(), 
      write_buffer: self.write_buffer.clone() 
    }
  }
  pub fn connect(tcp: &mut Tcp, dst_ip: Ipv4Addr, dst_port: u16) -> Result<TcpStream, String> {
    // Choose random available src_port
    let port = tcp.get_port();

    let seq_num = Tcp::gen_rand_u32();
    let ack_num = Tcp::gen_rand_u32();
    // Populate socket
    let socket = Socket {
      socket_id: tcp.next_unique_id(),
      status: SocketStatus::SynSent,
      tcp_socket: TcpSocket::Stream(TcpStream::new(SocketStatus::SynSent, seq_num, ack_num)),
    };

    let socket_key = SocketKey {
        local_ip: Some(tcp.src_ip),
        local_port: Some(port),
        remote_ip: Some(dst_ip),
        remote_port: Some(dst_port),
    };

    // Send SYN packet
    let packet = TcpPacket::new_syn(port, dst_port, seq_num, ack_num);
    tcp.send_packet(packet, dst_ip);
    loop {
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        socket_table.insert(socket_key.clone(), socket);
        break;
      }
    }

    // Wait to receive SYN + ACK response
    let mut status_cv = Arc::new((Mutex::new((SocketStatus::Closed, 0, 0)), Condvar::new()));
    loop {
      // Update socket table
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&socket_key).unwrap().tcp_socket{
          status_cv = Arc::clone(&stream.status);
        }
        break;
      }
    }
    {
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();

      // Wait to receive the SYN + ACK response
      while *pending_conns != (SocketStatus::Established, seq_num, ack_num + 1) {
        pending_conns = pend_cvar.wait(pending_conns).unwrap();
      }
    }

    // Send ACK packet
    let packet = TcpPacket::new(port, dst_port, seq_num, ack_num, 
      TcpFlags::ACK, Vec::new());
    tcp.send_packet(packet, dst_ip);
    
    loop {
      // Update socket table
      if let Ok(mut socket_table) = tcp.socket_table.try_lock() {
        socket_table.get_mut(&socket_key).unwrap().status = SocketStatus::Established;
        break;
      }
    }

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