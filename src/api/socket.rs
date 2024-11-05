use std::collections::btree_map::Range;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::collections::{HashMap,  VecDeque};
use std::sync::{Arc, Mutex, Condvar};

use crate::api::packet::{TcpFlags, TcpPacket};
use crate::api::tcp::{SocketKey, SocketStatus, TcpSocket};

use super::tcp::{Socket, Tcp};

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct TcpListener {
  // TODO: add a TcpListener struct to hold the TcpListener object (???)
  // A list of sockets for new/pending connections

  // This may not need to have Arc Mutex because it is being wrapped in the socket table.
  pub incoming_connections: Arc<(Mutex<VecDeque<Connection>>, Condvar)>,
  pub id: u32
}

impl TcpListener {
  pub fn clone(&self) -> TcpListener {
    TcpListener { 
      incoming_connections: Arc::clone(&self.incoming_connections),
      id: self.id
    }
  }

  pub fn listen(tcp: Arc<Mutex<Tcp>>, port: u16) -> Result<TcpListener, String> {
    // Search for next unique socket_id
    if let Ok(safe_tcp) = tcp.lock() {
      let socket_id = safe_tcp.next_unique_id();
      let tcp_listener = TcpListener {
        incoming_connections: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
        id: socket_id
      };
      
      let listening_socket = Socket::new(socket_id, SocketStatus::Listening, TcpSocket::Listener(tcp_listener.clone()));
      
      // Insert socket into socket table
      let socket_key = SocketKey {
          local_ip: None,
          local_port: Some(port),
          remote_ip: None,    
          remote_port: None,
      };
      safe_tcp.add_socket(socket_key, listening_socket);
      println!("Created listen socket with ID {}", socket_id);
      return Ok(tcp_listener);
    }
    return Err("Boo".to_string());
  }

  pub fn accept(&self, tcp_clone: Arc<Mutex<Tcp>>) -> Result<Socket, String> {
    let (lock, cvar) = &*self.incoming_connections;
    let connection;
    {
      let mut incoming_conns = lock.lock().unwrap();

      // Wait until a connection is available (receive SYN packet)
      while incoming_conns.is_empty() {
        incoming_conns = cvar.wait(incoming_conns).unwrap();
      }
      // Remove and return the first connection
      connection = incoming_conns.pop_front().unwrap();
    }
    
    let port = connection.socket_key.local_port.unwrap();
    let mut socket_table = Arc::new(Mutex::new(HashMap::new()));
    let mut status_cv = Arc::new((Mutex::new((SocketStatus::Closed, 0, 0)), Condvar::new()));
    if let Ok(tcp) = tcp_clone.lock() {
      // Create normal socket with this socket connection
      let socket = Socket {
        socket_id: tcp.next_unique_id(),
        status: SocketStatus::SynReceived,
        tcp_socket: TcpSocket::Stream(TcpStream::new(SocketStatus::SynReceived, connection.ack_num, connection.seq_num + 1))
      };
      
      // Send SYN + ACK packet
      let syn_ack_packet = TcpPacket::new_syn_ack(port, 
      connection.socket_key.remote_port.unwrap(), connection.ack_num, 
      connection.seq_num + 1);
      tcp.send_packet(syn_ack_packet, connection.socket_key.remote_ip.unwrap());
      // update socket table
      if let Ok(mut socket_table) = tcp.socket_table.lock() {
        socket_table.insert(connection.socket_key.clone(), socket);
      }

      // Get current status
      socket_table = tcp.socket_table.clone();
    }

    {
      if let Ok(mut socket_table) = socket_table.lock() {
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&connection.socket_key).unwrap().tcp_socket{
          status_cv = Arc::clone(&stream.status);
        }
      }
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();

      // Wait to receive the ACK response
      while *pending_conns != (SocketStatus::Established, connection.seq_num + 1, connection.ack_num + 1) {
        pending_conns = pend_cvar.wait(pending_conns).unwrap();
      }
      *pending_conns = (SocketStatus::Established, connection.ack_num + 1, connection.seq_num + 1);
    }
    // Update socket table
    if let Ok(mut table) = socket_table.lock() {
      let mut socket = table.get_mut(&connection.socket_key).unwrap();
      socket.status = SocketStatus::Established;
      println!("New connection on socket {} => created new socket {}", self.id, socket.socket_id);
      return Ok(table.get(&connection.socket_key).unwrap().clone());
    } 
    return Err("Boo".to_string());
  }

  pub fn add_connection(&self, connection: Connection) {
    let (lock, cvar) = &*self.incoming_connections;
    if let Ok(mut connections) = lock.lock() {
      // Add the new connection
      connections.push_back(connection);
    }
    
    // Notify waiting threads that a new connection is available
    cvar.notify_all(); // changed one to all
  }

  pub fn close(&self) -> Result<(), String> {
    // TODO: Implement TCP closing
    unimplemented!();
  }
}

#[derive(Clone, Debug)]
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
  pub fn connect(tcp_clone: Arc<Mutex<Tcp>>, dst_ip: Ipv4Addr, dst_port: u16) -> Result<TcpStream, String> {
    // Choose random available src_port
    let mut port= 0;
    let mut src_ip = Ipv4Addr::new(0,0,0,0) ;
    let mut socket_id = 0;
    if let Ok(tcp) = tcp_clone.lock() {
      port = tcp.get_port();
      socket_id = tcp.next_unique_id();
      src_ip = tcp.src_ip;
    }

    let seq_num = Tcp::gen_rand_u32();
    let ack_num = Tcp::gen_rand_u32();
    // Populate socket
    let socket = Socket {
      socket_id: socket_id,
      status: SocketStatus::SynSent,
      tcp_socket: TcpSocket::Stream(TcpStream::new(SocketStatus::SynSent, seq_num, ack_num)),
    };

    let socket_key = SocketKey {
        local_ip: Some(src_ip),
        local_port: Some(port),
        remote_ip: Some(dst_ip),
        remote_port: Some(dst_port),
    };

    // Send SYN packet
    let packet = TcpPacket::new_syn(port, dst_port, seq_num, ack_num);
    let mut status_cv = Arc::new((Mutex::new((SocketStatus::Closed, 0, 0)), Condvar::new()));
    for i in 0..2 {
      
    }
    if let Ok(tcp) = tcp_clone.lock() {
      tcp.send_packet(packet, dst_ip);
      if let Ok(mut socket_table) = tcp.socket_table.lock() {
        socket_table.insert(socket_key.clone(), socket);
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&socket_key).unwrap().tcp_socket{
          status_cv = Arc::clone(&stream.status);
        }
      }
    }

    {
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();

      // Wait to receive the SYN + ACK response
      while *pending_conns != (SocketStatus::Established, ack_num, seq_num + 1) {
        pending_conns = pend_cvar.wait(pending_conns).unwrap();
      }
      *pending_conns = (SocketStatus::Established, seq_num + 1, ack_num + 1);
    }

    // Send ACK packet
    let packet = TcpPacket::new(port, dst_port, seq_num + 1, ack_num + 1, 
      TcpFlags::ACK, Vec::new());
    if let Ok(tcp) = tcp_clone.lock() {
      tcp.send_packet(packet, dst_ip);
      // Update socket table
      if let Ok(mut socket_table) = tcp.socket_table.lock() {
        let socket = socket_table.get_mut(&socket_key).unwrap();
        socket.status = SocketStatus::Established;
        if let TcpSocket::Stream(stream) = &socket.tcp_socket {
          println!("Created new socket with ID {}", socket.socket_id);
          return Ok(stream.clone());
        };
      }
    }
    // otherwise, print out an error
    return Err("Nope".to_string());
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