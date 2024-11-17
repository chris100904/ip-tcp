use std::future::pending;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::collections::{HashMap,  VecDeque};
use std::sync::{Arc, Condvar, Mutex, WaitTimeoutResult};
use std::time::{Duration, Instant};
use chrono::Local;
use crate::api::packet::{TcpFlags, TcpPacket};
use crate::api::tcp::{SocketKey, SocketStatus, TcpSocket};

use super::buffer::{CircularBuffer, ReceiveBuffer, SendBuffer};
use super::error::TcpError;
use super::tcp::{Socket, Tcp};

pub const MAX_SEGMENT_SIZE: usize = 536;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct Connection {
  pub socket_key: SocketKey,
  pub seq_num: u32,
  pub ack_num: u32,
  pub window: u16,
}

impl Connection {
  pub fn clone(&self) -> Connection {
    Connection {
      socket_key: self.socket_key.clone(),
      seq_num: self.seq_num.clone(),
      ack_num: self.ack_num.clone(),
      window: self.window.clone(),
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

  pub fn listen(tcp: Arc<Mutex<Tcp>>, port: u16) -> Result<TcpListener, TcpError> {
    // Search for next unique socket_id
    {
      let safe_tcp = tcp.lock().unwrap();
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
  }

  pub fn accept(&self, tcp_clone: Arc<Mutex<Tcp>>) -> Result<Socket, TcpError> {
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
    
    let port = connection.socket_key.local_port
      .ok_or(TcpError::ConnectionError { message: "Local port not found".to_string() })?;
    let dst_port = connection.socket_key.remote_port
      .ok_or(TcpError::ConnectionError { 
        message: "Connection remote port not found".to_string() 
      })?;
    let dst_ip = connection.socket_key.remote_ip
      .ok_or(TcpError::ConnectionError { 
        message: "Connection remote ip not found".to_string() 
      })?;
    let socket_table;
    let status_cv;
    {
      let tcp = tcp_clone.lock().unwrap();
      // Create normal socket with this socket connection
      let socket = Socket {
        socket_id: tcp.next_unique_id(),
        status: SocketStatus::SynReceived,
        tcp_socket: TcpSocket::Stream(
          TcpStream::new(
            SocketStatus::SynReceived, 
            connection.seq_num, 
            connection.ack_num + 1, 
            connection.socket_key.clone()))
      };

      // Send SYN + ACK packet
      let syn_ack_packet = TcpPacket::new_syn_ack(port, 
      dst_port, connection.seq_num, connection.ack_num + 1);
      tcp.send_packet(syn_ack_packet, dst_ip);

      // update socket table
      {
        let mut socket_table = tcp.socket_table.lock().unwrap();
        socket_table.insert(connection.socket_key.clone(), socket);
      }

      // Get current status
      socket_table = tcp.socket_table.clone();
    }

    {
      {
        let mut socket_table = socket_table.lock().unwrap();
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&connection.socket_key).unwrap().tcp_socket {
          status_cv = Arc::clone(&stream.status);
        } else {
          // Socket not found
          return Err(TcpError::ListenerError { 
            message: "Socket table contained TcpListener rather than TcpStream.".to_string() 
          });
        }
      }
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();

      // Wait to receive the ACK response
      while !pending_conns.verify(SocketStatus::Established,
        connection.seq_num + 1,connection.ack_num + 1) {
        pending_conns = pend_cvar.wait(pending_conns).unwrap(); 
      }
      pending_conns.update(SocketStatus::Established, connection.seq_num + 1,
         connection.ack_num + 1, Some(connection.window));
    }

    let result = {
      let mut table = socket_table.lock().unwrap();
      let socket = table.get_mut(&connection.socket_key).ok_or(
        TcpError::ListenerError { 
          message: "Socket key not found in table.".to_string() 
        })?;
      // Your operations on `socket` here
      socket.status = SocketStatus::Established;

      // !!! BUFFER INITIALIZATION HERE !!!
      {
        if let TcpSocket::Stream(stream) = &mut socket.tcp_socket {
          let mut send_buffer = stream.send_buffer.0.lock().unwrap();
          let mut recv_buffer = stream.receive_buffer.0.lock().unwrap();

          send_buffer.lbw = connection.seq_num - 1;
          send_buffer.nxt = connection.seq_num;
          send_buffer.una = connection.seq_num;
          
          // ????????????
          recv_buffer.lbr = connection.ack_num;
          recv_buffer.nxt = connection.ack_num;
          println!("Initialized send and receive buffers with connection seq/ack info");
          println!("recv buffer lbr: {}", recv_buffer.lbr);
        }
    }
      Ok(socket.clone())
    };
  result
  }

  pub fn add_connection(&self, connection: Connection) {
    let (lock, cvar) = &*self.incoming_connections;
    { 
      let mut connections = lock.lock().unwrap();
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// TcpStream FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#[derive(Clone, Debug)]
pub struct RetransmissionEntry {
  seq_num: u32,
  data: Vec<u8>,
  timestamp: Instant,
  retries: u32, 
}

#[derive(Clone, Debug)]
pub struct TcpStream {
  // May not need to be arc mutexed.
  // Represents SocketStatus, seq_num, ack_num
  pub status: Arc<(Mutex<StreamInfo>, Condvar)>,

  pub socket_key: SocketKey,
  // TODO: add a TcpStream struct to hold the TcpStream object    
  // A buffer for reading data
  pub send_buffer: Arc<(Mutex<SendBuffer>, Condvar)>,  
  // A buffer for writing data
  pub receive_buffer: Arc<(Mutex<ReceiveBuffer>, Condvar)>,
  // In the sending case, you might consider keeping track of what packets 
  // you've sent and the timings for those in order to support retransmission 
  // later on, and in the receiving case, you'll need to handle receiving packets out of order.
  
  pub retransmission_queue: Arc<Mutex<VecDeque<RetransmissionEntry>>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct StreamInfo {
  pub status: SocketStatus,
  pub seq_num: u32,
  pub ack_num: u32,
  pub window_size: u16,
}

impl StreamInfo {
  pub fn new(status: SocketStatus, seq_num: u32, ack_num: u32, window_size: u16) -> StreamInfo {
    StreamInfo {
        status,
        seq_num,
        ack_num,
        window_size,
    }
  }

  // Returns true if self's status, seq_num, and ack_num all match
  pub fn verify(&self, status: SocketStatus, seq_num: u32, ack_num: u32) -> bool {
    return self.status == status && self.seq_num == seq_num && self.ack_num == ack_num;
  }

  pub fn update(&mut self, status: SocketStatus, seq_num: u32, 
    ack_num: u32, window_size: Option<u16>) {
      self.status = status;
      self.seq_num = seq_num;
      self.ack_num = ack_num;
      if let Some(window_size) = window_size {
        self.window_size = window_size;
      }
  }

  pub fn clone(&self) -> StreamInfo {
    StreamInfo {
        status: self.status.clone(),
        seq_num: self.seq_num,
        ack_num: self.ack_num,
        window_size: self.window_size,
    }
  }
}

impl TcpStream { 
  pub fn new(status: SocketStatus, seq_num: u32, ack_num: u32, socket_key: SocketKey) -> TcpStream {
    TcpStream { 
      status: Arc::new((Mutex::new(StreamInfo::new(status, seq_num, ack_num, 0)), Condvar::new())),
      socket_key,
      send_buffer: Arc::new((Mutex::new(SendBuffer::new()), Condvar::new())), 
      receive_buffer: Arc::new((Mutex::new(ReceiveBuffer::new()), Condvar::new())), 
      retransmission_queue: Arc::new(Mutex::new(VecDeque::new())),
    }
  }

  pub fn clone(&self) -> TcpStream {
    TcpStream { 
      status: Arc::clone(&self.status),
      socket_key: self.socket_key.clone(),
      send_buffer: self.send_buffer.clone(), 
      receive_buffer: self.receive_buffer.clone(),
      retransmission_queue: self.retransmission_queue.clone(),
    }
  }
  pub fn connect(tcp_clone: Arc<Mutex<Tcp>>, dst_ip: Ipv4Addr, dst_port: u16) -> Result<TcpStream, TcpError> {
    // Choose random available src_port
    let port;
    let src_ip;
    let socket_id;
   {
      let tcp = tcp_clone.lock().unwrap();
      port = tcp.get_port();
      socket_id = tcp.next_unique_id();
      src_ip = tcp.src_ip;
    }

    let seq_num = Tcp::gen_rand_u32();
    let ack_num = Tcp::gen_rand_u32();

    let socket_key = SocketKey {
        local_ip: Some(src_ip),
        local_port: Some(port),
        remote_ip: Some(dst_ip),
        remote_port: Some(dst_port),
    };

    // Populate socket
    let socket = Socket {
      socket_id: socket_id,
      status: SocketStatus::SynSent,
      tcp_socket: TcpSocket::Stream(TcpStream::new(SocketStatus::SynSent, seq_num, ack_num, socket_key.clone())),
    };

    // Send SYN packet
    let packet = TcpPacket::new_syn(port, dst_port, seq_num, ack_num);
    let status_cv ;
    {
      let tcp = tcp_clone.lock().unwrap();
      tcp.send_packet(packet.clone(), dst_ip);
      {
        let mut socket_table = tcp.socket_table.lock().unwrap();
        socket_table.insert(socket_key.clone(), socket);
        if let TcpSocket::Stream(stream) = &socket_table.get_mut(&socket_key).unwrap().tcp_socket { // TODO
          status_cv = Arc::clone(&stream.status);
        } else {
          return Err(TcpError::StreamError { message: "Tcp::connect unable to get stream from socket".to_string() });
        }
      }
    }

    for i in 0..4 {
      let (pend_lock, pend_cvar) = &*status_cv;
      let mut pending_conns = pend_lock.lock().unwrap();
      let mut timeout_result: Option<WaitTimeoutResult> = None;

      // Wait to receive the SYN + ACK response
      // Verify is always in the perspective of what we would send from our socket.
      if !pending_conns.verify(SocketStatus::Established, seq_num + 1, ack_num) { 
        (pending_conns, timeout_result) = pend_cvar.wait_timeout(pending_conns, 
          Duration::from_secs(2 + 2 * i))
        .map(|result| {
          (result.0, Some(result.1))
        }).unwrap();
      }

      if let Some(result) = timeout_result {
        if !result.timed_out() {
          pending_conns.update(SocketStatus::Established, seq_num + 1, 
            ack_num + 1, None);
          break;
        } else {
          let tcp = tcp_clone.lock().unwrap();
          if i == 3 {
            if let Ok(mut socket_table) = tcp.socket_table.lock() {
              socket_table.remove(&socket_key);
              eprintln!("Connect error: destination port does not exist.");
              return Err(TcpError::StreamError { message: "Connect error: destination port does not exist.".to_string() });
            }
          }
          eprintln!("{}  warn Connect retry attempt {}", Local::now().format("%Y-%m-%d %H:%M:%S"), i + 1);
          tcp.send_packet(packet.clone(), dst_ip);
        }
      }
    }

    // Send ACK packet
    let packet = TcpPacket::new(port, dst_port, seq_num + 1, ack_num + 1, 
      TcpFlags::ACK, Vec::new());
      println!("seq num: {}", seq_num);
    {
      let tcp = tcp_clone.lock().unwrap();
      tcp.send_packet(packet, dst_ip);
      // Update socket table
      let mut socket_table = tcp.socket_table.lock().unwrap();
      let socket = socket_table.get_mut(&socket_key).ok_or(
        TcpError::StreamError { message: "Could not retrieve TcpStream from socket table.".to_string() }
      )?;
      socket.status = SocketStatus::Established;

      // !!! INITIALIZE BUFFERS HERE !!!
      {
        if let TcpSocket::Stream(stream) = &mut socket.tcp_socket {
          let mut send_buffer = stream.send_buffer.0.lock().unwrap();
          let mut receive_buffer = stream.receive_buffer.0.lock().unwrap();
          send_buffer.lbw = seq_num;
          send_buffer.nxt = seq_num + 1;
          send_buffer.una = seq_num + 1;

          receive_buffer.lbr = ack_num;
          receive_buffer.nxt = ack_num + 1;
          println!("Initialized send and receive buffers with sequence and acknowledgment numbers.");
        }
      };
      if let TcpSocket::Stream(stream) = &socket.tcp_socket {
        println!("Created new socket with ID {}", socket.socket_id);
        
        return Ok(stream.clone());
      };
    }
    return Err(TcpError::StreamError {
      message: "Could not complete connect.".to_string()
    });
  }

  // TODO
  pub fn read(&mut self, bytes_to_read: u32) -> Result<Vec<u8>, TcpError> {
      let mut recv_buffer = self.receive_buffer.0.lock().unwrap();
      
      let available_bytes = recv_buffer.nxt.wrapping_sub(recv_buffer.lbr).wrapping_add(1);
      let lbr = recv_buffer.lbr;
      println!("lbr: {}", lbr);
      let bytes_to_return = std::cmp::min(available_bytes, bytes_to_read);

      if bytes_to_return == 0 {
        // handle if there is nothing
        // BLOCK
      }

      // want to start reading from lbr + 1, first non read byte
      let data = recv_buffer.buffer.read(lbr + 1, bytes_to_return);
      println!("{:?}",data);
      // recv_buffer.lbr = recv_buffer.lbr.wrapping_add(bytes_to_return);
      recv_buffer.consume(bytes_to_return);
      Ok(data)
  }

  pub fn write(&mut self, buf: &[u8]) -> Result<usize, TcpError> {
      let mut send_buffer = self.send_buffer.0.lock().unwrap();
      let lbw = send_buffer.write(buf);

      // Notify sending thread that new bytes have been written into the buffer
      self.send_buffer.1.notify_all();
      
      Ok(0)
  }   

  pub fn close(&self) -> Result<(), TcpError> {
      // TODO: Implement TCP closing
      unimplemented!();
  }

  // Called on a separate thread.
  pub fn send_bytes(&mut self, tcp_clone: Arc<Mutex<Tcp>>) {
    let (buffer_lock, cvar) = &*self.send_buffer;
    loop {
      let mut bytes_to_send;
      {
        let mut send = buffer_lock.lock().unwrap();
        send = cvar.wait(send).unwrap();
        bytes_to_send = send.lbw.wrapping_sub(send.nxt).wrapping_add(1) as i64;
      }
      
      let tcp = Arc::clone(&tcp_clone);
      let mut available_bytes: i64;
      // Check to see if there are bytes in the buffer that have not been sent yet
      while bytes_to_send > 0 {
        let mut send = buffer_lock.lock().unwrap();
        { 
          // Available Bytes = Window size since last ACK - unacknowledged bytes that have been sent
          // TEMPORARY CHANGE: WINDOW SIZE SHOULD BE LBW 
          available_bytes = self.status.0.lock().unwrap().window_size as i64 - send.nxt.wrapping_sub(send.una) as i64;
          // available_bytes = send.lbw.wrapping_sub(send.nxt).wrapping_add(1) as i64;
          println!("available bytes: {} = win: {} - (nxt: {} - una: {})", available_bytes, self.status.0.lock().unwrap().window_size, send.nxt, send.una);
          // println!("available bytes: {} = lbw: {} - nxt: {}", available_bytes, send.lbw, send.nxt);
        }

        if available_bytes <= 0 {
          // Wait for non-zero size
          // Send next byte you would want to send
          todo!("Zero-window probing");
        }
        
        // Construct packet with an appropriate number of bytes
        let send_bytes_length: u32 = bytes_to_send
          .min(MAX_SEGMENT_SIZE as i64)
          .min(available_bytes as i64).try_into().unwrap();

        // let start = send.buffer.seq_to_index(send.nxt);
        // let end = send.buffer.seq_to_index(send.nxt + send_bytes_length);
        // let mut send_bytes = vec![0; end - start]; 
        // println!("{:?}", &send.buffer.buffer[start..end]);
        // send_bytes.copy_from_slice(&send.buffer.buffer[start..end]);
        let nxt = send.nxt;
        let send_bytes = send.buffer.read(nxt, send_bytes_length);
        println!("{:?}", send_bytes);
        let seq_num;
        let ack_num;
        let wnd;
        {
          let stream_info = self.status.0.lock().unwrap();
          seq_num = stream_info.seq_num;
          ack_num = stream_info.ack_num;
          wnd = self.receive_buffer.0.lock().unwrap().wnd;
        }
        

        let packet = TcpPacket::new_ack(self.socket_key.local_port.unwrap(), 
        self.socket_key.remote_port.unwrap(),
          seq_num, ack_num, wnd, send_bytes);

        {
          let safe_tcp = tcp.lock().unwrap();
          safe_tcp.send_packet(packet, self.socket_key.remote_ip.unwrap());
        }
    
        // Adjust send.nxt
        send.nxt += send_bytes_length as u32;
        // Recalculate bytes_to_send
        bytes_to_send = (send.lbw as i64) - (send.nxt as i64);
      }
    }
  }
}