use std::{collections::{HashMap, HashSet}, fs::File, io::{BufReader, Read, Write}, net::Ipv4Addr, sync::{mpsc::{Receiver, Sender}, Arc, Condvar, Mutex}, time::{Instant, Duration}, u32::MAX};
use std::thread;
use rand::Rng;

use crate::api::socket::MAX_SEGMENT_SIZE;

use super::{error::TcpError, packet::{Packet, TcpFlags, TcpPacket}, socket::{self, Connection, TcpListener, TcpStream, RTEntry}, TCPCommand};

pub const MSL: usize = 5;

#[derive(Hash, Eq, PartialEq, Clone, Debug, Copy)]
pub struct SocketKey {
    pub local_ip: Option<Ipv4Addr>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: Option<u16>,
}

impl SocketKey {
  pub fn clone(&self) -> SocketKey {
    SocketKey { 
      local_ip: self.local_ip, 
      local_port: self.local_port, 
      remote_ip: self.remote_ip, 
      remote_port: self.remote_port
    }
  }
}

// initialize tcp struct with a socket table
pub struct Tcp {
    pub src_ip: Ipv4Addr,
    pub tcp_send_ip: Sender<(TcpPacket, Ipv4Addr)>,
    pub socket_table: Arc<Mutex<HashMap<SocketKey, Socket>>>,
    pub used_ports: Arc<Mutex<HashSet<u16>>>,
    pub rto_min: u64,
    pub rto_max: u64,
}

#[derive(Clone, Debug)]
pub enum TcpSocket {
    Listener(TcpListener),
    Stream(TcpStream),
}

// Being used by listen_accept (and perhaps other places as well) to handle the state of a socket w/ condvar
pub struct ListenerHandle {
    port: u16,
    stop_signal: Arc<(Mutex<bool>, Condvar)>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

/* 
    I think this is all from the rfc9293 thing, but I'm not sure if we need every single one of these in our project?
*/
#[derive(PartialEq, Clone, Debug)]
pub enum SocketStatus {
    Closed,
    Listening,
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    Closing,
    ClosedWait,
    LastAck,
}

impl SocketStatus {
  pub fn to_string(&self) -> String {
    match self {
        SocketStatus::Closed => "",
        SocketStatus::Listening => "LISTEN",
        SocketStatus::Established => "ESTABLISHED",
        SocketStatus::SynSent => "SYN-SENT",
        SocketStatus::SynReceived => "SYN-RECEIVED",
        SocketStatus::FinWait1 => "FIN-WAIT1",
        SocketStatus::FinWait2 => "FIN-WAIT2",
        SocketStatus::TimeWait => "TIME-WAIT",
        SocketStatus::Closing => "CLOSING",
        SocketStatus::ClosedWait => "CLOSED-WAIT",
        SocketStatus::LastAck => "LAST-ACK",
    }.to_string()
  }
}

// socket struct definition
#[derive(Clone, Debug)]
pub struct Socket {
    pub socket_id: u32,
    pub status: Arc<Mutex<SocketStatus>>,
    pub tcp_socket: TcpSocket, 
}

impl Socket {
    pub fn new(socket_id: u32, status: SocketStatus, tcp_socket: TcpSocket) -> Socket {
        Socket {
            socket_id,
            status: Arc::new(Mutex::new(status)), 
            tcp_socket
        }
    }
    
    pub fn clone(&self) -> Socket {
      Socket {
        socket_id: self.socket_id,
        status: Arc::clone(&self.status),
        tcp_socket: self.tcp_socket.clone(),
    }
    }
}

impl Tcp {
    pub fn new(tcp_send_ip: Sender<(TcpPacket, Ipv4Addr)>, src_ip: Ipv4Addr, rto_min: u64, rto_max: u64) -> Tcp {
        Tcp {
          src_ip,
          tcp_send_ip,
          socket_table: Arc::new(Mutex::new(std::collections::HashMap::new())),
          used_ports: Arc::new(Mutex::new(HashSet::<u16>::new())),
          rto_min,
          rto_max,
        }
    }

    /* 
        I'm assuming that there is going to be a tcp protocol handler here as well, similar to how it is in `device.rs`?
        Not really sure if we need to have device being imported? 

        Also need to double check all data types are correct
     */
    pub fn tcp_protocol_handler(tcp: Arc<Mutex<Tcp>>, receiver: Receiver<TCPCommand>) {
      loop {
        let tcp_clone = Arc::clone(&tcp);
          match receiver.recv() {
              Ok(command) => {
                  let result: Result<_, TcpError> = match command {
                      TCPCommand::ListenAccept(port) => Tcp::listen_and_accept(tcp_clone, port),
                      TCPCommand::TCPConnect(vip, port) => Tcp::connect(&tcp, vip, port),
                      TCPCommand::ListSockets => tcp.lock().unwrap().list_sockets(),
                      TCPCommand::TCPSend(socket_id, bytes) => Tcp::send_data(tcp_clone, socket_id, bytes),
                      TCPCommand::TCPReceive(socket_id, numbytes) => Tcp::receive_data(tcp_clone, socket_id, numbytes),
                      TCPCommand::TCPClose(socket_id) => Tcp::close_socket(tcp_clone, socket_id, true),
                      TCPCommand::SendFile(path, addr, port) => Tcp::send_file(tcp_clone, path, addr, port),
                      TCPCommand::ReceiveFile(path, port) => Tcp::receive_file(tcp_clone, path, port),
                  };
                  if let Err(e) = result {
                    eprintln!("{e}");
                  }
              }
              Err(_) => break,
          }
      }
    }

    pub fn send_data(tcp: Arc<Mutex<Self>>, socket_id: u32, bytes: String) -> Result<(), TcpError> {
      // find the socket by ID
      let socket;
      {
        let safe_tcp = tcp.lock().unwrap();
        (_, socket) = safe_tcp.get_socket_by_id(socket_id)
          .ok_or(TcpError::ConnectionError { message: format!("Socket ID {} not recognized.", socket_id) })?;
      }

      {
        let socket_status = socket.status.lock().unwrap();
        // check if the socket is valid and established
        if *socket_status != SocketStatus::Established {
          // whatever error here
          return Err(TcpError::ConnectionError { 
            message: format!("Invalid socket status for socket {}: {}", socket.socket_id, socket_status.to_string()) 
          })
        }
      }
      
      // get the TcpStream from the socket
      
      // translate into bytes and write into the send buffer
      match socket.tcp_socket {
        TcpSocket::Stream(mut stream) => {
          let data = bytes.as_bytes();
          // println!("{:?}", data);
          // println!("184 STARTING SEQ: {}", stream.status.0.lock().unwrap().seq_num);
          let result = stream.write(data);
        },
        TcpSocket::Listener(_) => {
          return Err(TcpError::ConnectionError { message: "Socket was of type Listener rather than Stream.".to_string() });
        }
      }

      return Ok(());
    }

    pub fn receive_data(tcp_clone: Arc<Mutex<Tcp>>, socket_id: u32, bytes: u32) -> Result<(), TcpError> {
      // find the socket by ID
      let socket;
      {
        let safe_tcp = tcp_clone.lock().unwrap();
        (_, socket) = safe_tcp.get_socket_by_id(socket_id)
          .ok_or(TcpError::ConnectionError { message: format!("Socket ID {} not recognized.", socket_id) })?;
      }

      {
        let socket_status = socket.status.lock().unwrap();
        // check if the socket is valid and established
        if *socket_status != SocketStatus::Established {
          // whatever error here
          return Err(TcpError::ConnectionError { 
            message: format!("Invalid socket status for socket {}: {}", socket.socket_id, socket_status.to_string()) 
          })
        }
      }
      // get the TcpStream from the socket
      
      // read the designated amount (or less) from the buffer
      match socket.tcp_socket {
        TcpSocket::Stream(mut stream) => {
          let result = stream.read(bytes);
          match result {
            Ok(bytes_read) => {
              println!("Read {} bytes: {}", bytes_read.len(), String::from_utf8_lossy(&bytes_read));
              Ok(())
            },
            Err(e) => Err(e), // HANDLE THIS ERROR????
          }
        },
        TcpSocket::Listener(_) => {
          return Err(TcpError::ConnectionError { message: "Socket was of type Listener rather than Stream.".to_string() });
        }
      }

      // return Ok(());
    }

    pub fn listen_and_accept(tcp: Arc<Mutex<Self>>, port: u16) -> Result<(), TcpError> { 
        let tcp_listener = TcpListener::listen(Arc::clone(&tcp), port)?;

        let tcp_clone = Arc::clone(&tcp);
        thread::spawn(move || {
            loop {
              let tcp = Arc::clone(&tcp_clone);
                let tcp_clone_2 = Arc::clone(&tcp);
                let tcp_clone_3 = Arc::clone(&tcp);
                match tcp_listener.accept(tcp) {
                  Ok(socket) => {
                    if let TcpSocket::Stream(mut stream) = socket.tcp_socket {
                      let mut stream_clone = stream.clone();
                      thread::spawn( move || {
                        stream.send_bytes(tcp_clone_2);
                      });
                      thread::spawn( move || {
                        stream_clone.retransmit(tcp_clone_3);
                      });
                    }
                  },
                  Err(e) => {
                    eprintln!("{e}");
                  }
                }
            }
        });
      Ok(())
    }

    pub fn stop_listening(&self, handle: &mut ListenerHandle) {
        // Destructure the stop_signal into its Mutex and Condvar components
        let (lock, cvar) = &*handle.stop_signal;
        {
          // Acquire the lock on the stop flag
          let mut stop = lock.lock().unwrap();
          
          // Set the stop flag to true
          *stop = true;
        }
        // Notify one waiting thread (the listener thread) that the stop flag has changed
        cvar.notify_all();

        // Check if the thread handle exists, and if so, take ownership of it
        if let Some(thread) = handle.thread_handle.take() {
            // Wait for the listener thread to finish
            thread.join().unwrap();
        }

        // Create a SocketKey for the listening socket
        let socket_key = SocketKey {
            local_ip: None,
            local_port: Some(handle.port),
            remote_ip: None,
            remote_port: None,
        };
        
        // Remove the listening socket from the socket table
        self.remove_socket(&socket_key);
    }

    // Receive a packet
    pub fn receive_packet(tcp_clone: Arc<Mutex<Tcp>>, packet: Packet) -> Result<(), TcpError> {
      let tcp_packet = TcpPacket::parse_tcp(packet.src_ip, packet.dst_ip, &packet.payload)
        .map_err(|e| TcpError::ConnectionError { message: format!("Error parsing packet. Source: {}", e) })?;
      // NOTE: src_ip and dest_ip and ports are FLIPPED because we want to check if the dest_ip is our source_ip, etc. 
      let socket_key = SocketKey {
        local_ip: Some(packet.dst_ip),
        local_port: Some(tcp_packet.dst_port),
        remote_ip: Some(packet.src_ip),
        remote_port: Some(tcp_packet.src_port),
      };

      // println!("{:?}", tcp_packet.flags);
      match tcp_packet.flags {
        flag if flag == TcpFlags::SYN => {
          // Check if tcp_packet.dst_port is a LISTEN port (src_port in socket table)
          let mut socket;
          {
            socket = tcp_clone.lock().unwrap().is_listen(tcp_packet.dst_port);
          }
          if let Some(listen_socket) = socket {
            Ok(if let TcpSocket::Listener(ref listen_conn) = listen_socket.tcp_socket {
              // Acquire lock to check for existing connection
              let already_exists = {
                  let incoming_connections = listen_conn.incoming_connections.0.lock().unwrap(); // TODO
                  incoming_connections.iter().any(|conn| conn.socket_key == socket_key)
              }; // Lock is released here as `incoming_connections` goes out of scope
              
              if !already_exists {
                  // Add connection if not already present
                  // Connection should contain values that should be values of the new connection
                  let connection = Connection {
                      socket_key,
                      seq_num: tcp_packet.ack_num,
                      ack_num: tcp_packet.seq_num,
                      window: tcp_packet.window,
                  };
                  listen_conn.add_connection(connection); // Safe to call `add_connection` here
              }
            })
          } else {
            // If not, drop the packet.
            return Err(TcpError::ConnectionError { message: "SYN: No listening socket found.".to_string() });
          }
        },
        flag if flag == TcpFlags::SYN | TcpFlags::ACK => {
          // Check if connection is already in the socket table and has status SYN-SENT
          let mut opt_socket;
          {
            opt_socket = tcp_clone.lock().unwrap().get_socket(socket_key);
          }
          Ok(if let Some(socket) = opt_socket {
            let socket_status;
            {
              socket_status = socket.status.lock().unwrap().clone();
            }
            if socket_status == SocketStatus::SynSent {
              // If so, then proceed with connect (send the ACK) and establish the connection
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                lock.lock().unwrap().update(Some(SocketStatus::Established), Some(tcp_packet.ack_num), 
                Some(tcp_packet.seq_num), Some(tcp_packet.window));

                // Notify waiting threads that a new connection is available
                cvar.notify_all(); // changed one to all
              } else {
                return Err(TcpError::ConnectionError { message: "Socket found was not a TcpStream.".to_string() });
              }
            } else {
              return Err(TcpError::ConnectionError { message: "No socket found.".to_string() });
            }
          })
          // If not, drop the packet.
        },
        flag if flag == TcpFlags::ACK => {
          // Check if connection is already in the socket table and has status SYN-RECEIVED
          let mut opt_socket;
          {
            opt_socket = tcp_clone.lock().unwrap().get_socket(socket_key);
          }
          Ok(if let Some(mut socket) = opt_socket {
            let socket_status;
            {
              socket_status = socket.status.lock().unwrap().clone();
            }
            if socket_status == SocketStatus::SynReceived {
              // If so, then finish accept() and establish the connection
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                {
                  lock.lock().unwrap().update(Some(SocketStatus::Established), Some(tcp_packet.ack_num), 
                    Some(tcp_packet.seq_num), Some(tcp_packet.window));
                }
                // Notify waiting threads that a new connection is available
                cvar.notify_all(); // changed one to all
              } else {
                return Err(TcpError::ConnectionError { message: "Could not find expected TcpStream.".to_string() });
              }
            } else if socket_status == SocketStatus::Established {
              // Update socket's ack num, seq num, and window size
              // Notify the thread looking to update the buffers in response to these.
              // Specifically, if the ACK number / window size changed, then update the send_buffer.
              // If there is data in the payload, then the receive_buffer should be changed.
              println!("received ACK {}", tcp_packet.ack_num);
              if let TcpSocket::Stream(mut stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                {
                  let (send_lock, send_cv, send_write_cv) = &*stream.send_buffer;
                  let mut send_buf = send_lock.lock().unwrap();
                  if tcp_packet.ack_num > send_buf.una {
                    println!("Received ack {} is higher than our send.una {}, updating window size", tcp_packet.ack_num, send_buf.una);
                    send_buf.una = tcp_packet.ack_num;
                    send_write_cv.notify_all();
                    {
                      lock.lock().unwrap().update(None, 
                        None, None,
                         Some(tcp_packet.window));
                    }
                    if tcp_packet.window > 0 {
                      println!("cvar notify! (tcp.rs:418)");
                      cvar.notify_all();
                    }
                  }
                  {
                    println!("421");
                    // Remove acknowledged packets from retransmission queue
                    let mut rtq = stream.rtq.0.lock().unwrap();
                    let mut updated_rtt = false; // Flag to track if RTT/SRTT was updated
                    rtq.retain(|entry| {
                        // Check if packet is acknowledged
                        if entry.packet.seq_num + (entry.packet.payload.len() as u32) <= tcp_packet.ack_num {
                            // Calculate RTT only for the first packet being removed
                            if !updated_rtt && entry.retries == 0 {
                                let measured_rtt = entry.timestamp.elapsed().as_micros() as u64;
                                let mut srtt = stream.srtt.lock().unwrap();
                                let mut rto = stream.rto.lock().unwrap();
                                if *srtt == 0 {
                                    // Initialize SRTT and RTO
                                    *srtt = measured_rtt;
                                    *rto = *srtt + (4 * (measured_rtt / 2));
                                } else {
                                    println!("PREV SRTT: {}", *srtt);
                                    let measured_rtt_f64 = measured_rtt as f64;
                                    let srtt_f64 = *srtt as f64;
                                    *srtt = ((7.0 / 8.0) * srtt_f64 + (1.0 / 8.0) * measured_rtt_f64) as u64;
                                    println!("POST SRTT: {}", *srtt);
                                    
                                    // Update RTO with clamping
                                    let (rto_min, rto_max) = {
                                        let tcp = tcp_clone.lock().unwrap();
                                        (tcp.rto_min.clone(), tcp.rto_max.clone())
                                    };
                                    let rto_f64 = (1.3 * *srtt as f64).clamp(rto_min as f64, rto_max as f64);
                                    *rto = rto_f64 as u64;
                                    println!("Measured RTT: {}, SRTT: {}, RTO: {}", measured_rtt, *srtt, *rto);
                                }
                                updated_rtt = true; // Mark that RTT/SRTT was updated for this ACK
                            }
                            false // Remove this entry
                        } else {
                            true // Keep this entry
                        }
                    });
                  }
                }
                let (recv_lock, recv_cv) = &*stream.receive_buffer;
                let mut recv_buf = recv_lock.lock().unwrap();

                // TODO: SET NXT VALUE
                // TODO: THINK OF A BETTER WAY TO GET THE VALUES OF THE ACK RESPONSE PACKET
                if tcp_packet.payload.len() != 0 {
                  println!("NXT: {}, SEQ RECEIVED: {}", recv_buf.nxt, tcp_packet.seq_num);
                  println!("ACK: {}", tcp_packet.ack_num);
                  println!("Received packet with data! SEQ: {}, NXT: {}", tcp_packet.seq_num, recv_buf.nxt);
                  let mut status = lock.lock().unwrap();
                  if tcp_packet.seq_num >= recv_buf.nxt {
                    // println!("Writing {} into recv_buf at position {}", String::from_utf8_lossy(&tcp_packet.payload), tcp_packet.seq_num);
                    let _ = recv_buf.write(tcp_packet.seq_num, &tcp_packet.payload);
                    recv_cv.notify_all();
                    status.update(None, None, Some(recv_buf.nxt), None);
                  } 
                  let src_port = tcp_packet.dst_port;
                  let dst_port = tcp_packet.src_port;
                  let ack_response = TcpPacket::new_ack(
                    src_port,
                    dst_port, 
                    status.seq_num, 
                    status.ack_num, 
                    recv_buf.wnd, 
                    Vec::new());
                  println!("Ack response: SEQ: {} ACK: {} WND: {}", ack_response.seq_num, ack_response.ack_num, ack_response.window);
                  tcp_clone.lock().unwrap().send_packet(ack_response, packet.src_ip);
                }
              }
            } else if socket_status == SocketStatus::FinWait1 {
              // Making sure that the ACK number received is greater than our current SEQ number by 1
              // If so, then transition to FIN-WAIT2
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                {
                  let mut status = stream.status.0.lock().unwrap();
                  if status.seq_num + 1 == tcp_packet.ack_num {
                    // transition to FIN-WAIT2
                    // !!! There shouldn't be a need for updating seq num and ack num here? Just the status 
                    status.update(Some(SocketStatus::FinWait2), None, None, None);
                    *socket.status.lock().unwrap() = SocketStatus::FinWait2;
                    println!("490: update to FINWAIT2");
                  } else {
                    return Err(TcpError::ConnectionError { message: ("Received ACK for FINWAIT1, seq num was wrong").to_string() })
                  }
                }
                {
                  // Remove acknowledged packets from retransmission queue
                  let mut rtq = stream.rtq.0.lock().unwrap();
                  rtq.retain(|entry| entry.packet.seq_num + (entry.packet.payload.len() as u32) > tcp_packet.ack_num);
                }
              }
            } else if socket_status == SocketStatus::Closing {
              // transition to TIME WAIT
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                {
                  // !!! i'm worried these are wrong
                  let mut status = lock.lock().unwrap();
                  if status.seq_num + 1 == tcp_packet.ack_num {
                    status.update(Some(SocketStatus::TimeWait), Some(tcp_packet.ack_num), Some(tcp_packet.seq_num + 1), None);
                    *socket.status.lock().unwrap() = SocketStatus::TimeWait;
                  }
                }
                {
                  // Remove acknowledged packets from retransmission queue
                  let mut rtq = stream.rtq.0.lock().unwrap();
                  rtq.retain(|entry| entry.packet.seq_num + (entry.packet.payload.len() as u32) > tcp_packet.ack_num);
                }
              }
            } else if socket_status == SocketStatus::LastAck {
              println!("519");
              // If you receive an ACK that is 1 greater than current SEQ, then can transition to CLOSED and initiate teardown
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                {
                  let mut status = stream.status.0.lock().unwrap();
                  if status.seq_num + 1 == tcp_packet.ack_num {
                    status.update(Some(SocketStatus::Closed), None, None, None);
                    *socket.status.lock().unwrap() = SocketStatus::Closed;
                  }
                }

                {
                  // Remove acknowledged packets from retransmission queue
                  let mut rtq = stream.rtq.0.lock().unwrap();
                  rtq.retain(|entry| entry.packet.seq_num + (entry.packet.payload.len() as u32) > tcp_packet.ack_num);
                }

                // initiate TCB teardown
                stream.teardown_connection();
                
                tcp_clone.lock().unwrap().remove_socket(&socket_key);
              }
            } else {
              // If not, drop the packet.
              return Err(TcpError::ConnectionError { message: "LastAck: No listening socket found.".to_string() });
            }
            
          })
        },
        flag if flag == TcpFlags::RST => {
          // Should terminate the connection
          todo!()
        },
        flag if flag == TcpFlags::FIN => {
          // Check if connection is already in the socket table
          // Valid statuses: ESTABLISHED, FIN-WAIT1, FIN-WAIT2
          let opt_socket;
          {
            opt_socket = tcp_clone.lock().unwrap().get_socket(socket_key);
          }
          Ok(if let Some(mut socket) = opt_socket {
            // If we are ESTABLISHED, we want to send an ACK acknowledging the FIN
            // and transition to CLOSE_WAIT. We also want to initiate our closing process, so call close_socket 
            let socket_status;
            {
              socket_status = socket.status.lock().unwrap().clone();
            }
            if socket_status == SocketStatus::Established {
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let ack_response;
                {
                  let mut status = stream.status.0.lock().unwrap();
                  // update everything except for our own window size 
                  status.update(Some(SocketStatus::ClosedWait), None, 
                    Some(tcp_packet.seq_num + 1), None);
                    *socket.status.lock().unwrap() = SocketStatus::ClosedWait;
                  // send an ACK
                  ack_response = TcpPacket::new_ack(
                    tcp_packet.dst_port,
                    tcp_packet.src_port,
                    status.seq_num,
                    status.ack_num,
                    stream.receive_buffer.0.lock().unwrap().wnd,
                    Vec::new()
                  );
                }
                println!("584: update to CLOSED WAIT");
                println!("Ack response: SEQ: {} ACK: {} WND: {}", ack_response.seq_num, ack_response.ack_num, ack_response.window);
                tcp_clone.lock().unwrap().send_packet(ack_response, packet.src_ip);

                // initiate closing
                Tcp::close_socket(tcp_clone, socket.socket_id, false)?;
              }
            }
            // If we are FIN-WAIT1, we want to send an ACK acknowledging the FIN and transition to CLOSING
            else if socket_status == SocketStatus::FinWait1 {
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let ack_response;
                {
                  let mut status = stream.status.0.lock().unwrap();
                  // update everything except for our own window size 
                  status.update(Some(SocketStatus::Closing), Some(tcp_packet.ack_num), 
                    Some(tcp_packet.seq_num + 1), None);
                    *socket.status.lock().unwrap() = SocketStatus::Closing;
                  // send an ACK
                  ack_response = TcpPacket::new_ack(
                    tcp_packet.dst_port,
                    tcp_packet.src_port,
                    status.seq_num,
                    status.ack_num,
                    stream.receive_buffer.0.lock().unwrap().wnd,
                    Vec::new());
                    println!("Ack response: SEQ: {} ACK: {} WND: {}", ack_response.seq_num, ack_response.ack_num, ack_response.window);
                    tcp_clone.lock().unwrap().send_packet(ack_response, packet.src_ip);
                }
              }
            }
            // If we are FIN-WAIT2, we want to send an ACK acknowledging the FIN and transition to TIME_WAIT 
            else if socket_status == SocketStatus::FinWait2 {
              println!("618 FINWAIT2");
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                {
                  let mut status = stream.status.0.lock().unwrap();
                  status.update(Some(SocketStatus::TimeWait), None, Some(tcp_packet.seq_num + 1), None);
                  *socket.status.lock().unwrap() = SocketStatus::TimeWait;
                  println!("625: update to TIMEWAIT, sending ACK");
                  // send an ACK
                  let ack_repsonse = TcpPacket::new_ack(
                    tcp_packet.dst_port,
                    tcp_packet.src_port,
                    status.seq_num,
                    status.ack_num,
                    stream.receive_buffer.0.lock().unwrap().wnd,
                    Vec::new()
                  );
                  println!("Ack response: SEQ: {} ACK: {} WND: {}", ack_repsonse.seq_num, ack_repsonse.ack_num, ack_repsonse.window);
                  tcp_clone.lock().unwrap().send_packet(ack_repsonse, packet.src_ip);
                }

                // Start TIME_WAIT timer
                let socket_id = socket.socket_id;
                let tcp_for_timer = Arc::clone(&tcp_clone);
                
                thread::spawn(move || {
                    // Wait for 2*MSL
                    thread::sleep(Duration::from_secs((2 * MSL).try_into().unwrap()));
                    
                    // After 2*MSL, initiate connection teardown
                    let tcp = tcp_for_timer.lock().unwrap();
                    if let Some((_, socket)) = tcp.get_socket_by_id(socket_id) {
                      if let TcpSocket::Stream(stream) = socket.tcp_socket {
                        stream.teardown_connection();
                      }
                    }
                    // Thread exits automatically
                });
                // clean up anything here in TCP
                tcp_clone.lock().unwrap().remove_socket(&socket_key);
              }
            } else {
              println!("{}", socket_status.to_string());
                return Err(TcpError::ConnectionError { message: "Wrong socket status".to_string() });
            }
          })
        },
        flag if flag == TcpFlags::FIN | TcpFlags::ACK => {
          // Check if connection is already in the socket table
          // Valid statuses: FIN-WAIT1
          // Update status to TIME WAIT and send an ACK
          let opt_socket;
          {
            opt_socket = tcp_clone.lock().unwrap().get_socket(socket_key);
          }
          Ok(if let Some(mut socket) = opt_socket {
            let socket_status;
            {
              socket_status = socket.status.lock().unwrap().clone();
            }
            if socket_status == SocketStatus::FinWait1 {
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                {
                  // update everything except for our own window size 
                  lock.lock().unwrap().update(Some(SocketStatus::TimeWait), Some(tcp_packet.ack_num), 
                    Some(tcp_packet.seq_num + 1), None);
                  *socket.status.lock().unwrap() = SocketStatus::TimeWait;
                }
                let status = lock.lock().unwrap();
                let (recv_lock, recv_cv) = &*stream.receive_buffer;
                let recv_buf = recv_lock.lock().unwrap();
                
                // send an ACK
                let ack_repsonse = TcpPacket::new_ack(
                tcp_packet.dst_port,
                tcp_packet.src_port,
                status.seq_num,
                status.ack_num,
                recv_buf.wnd,
                Vec::new());
                println!("Ack response: SEQ: {} ACK: {} WND: {}", ack_repsonse.seq_num, ack_repsonse.ack_num, ack_repsonse.window);
                tcp_clone.lock().unwrap().send_packet(ack_repsonse, packet.src_ip);

                // initiate timeout

                // if timeout is good, update to closed
                {
                  lock.lock().unwrap().update(Some(SocketStatus::Closed), None, None, None);
                  *socket.status.lock().unwrap() = SocketStatus::Closed;
                }

                // initiate TCB teardown
                stream.teardown_connection();

                // clean up anything in tcp here
                tcp_clone.lock().unwrap().remove_socket(&socket_key);
              }
            }
          })
        },
        _ => {
          // Drop the packet
          return Err(TcpError::ConnectionError { message: "Packet did not contain valid flags. Dropping.".to_string() });
        }
      }
    }

    pub fn send_packet(&self, packet: TcpPacket, dst_ip: Ipv4Addr) {
      // println!("Sent {:?}", String::from_utf8_lossy(&packet.payload));
      self.tcp_send_ip.send((packet, dst_ip));
    }

    pub fn gen_rand_u32() -> u32 {
      return 0;
      // let mut rng = rand::thread_rng();
      // return rng.gen();
    }

    // Generates random available port number using the used_ports hashset. Does NOT insert into the hashset.
    pub fn get_port(&self) -> u16 {
      loop {
        let mut rng = rand::thread_rng();
        let port = rng.gen_range(20_000..=u16::MAX);
        if let Ok(used_ports) = self.used_ports.lock() {
          if !used_ports.contains(&port) {
            return port;
          }
        }
      }
    }

    pub fn connect(tcp: &Arc<Mutex<Self>>, vip: Ipv4Addr, port: u16) -> Result<(), TcpError> {
      // Create new normal socket
      let mut stream = TcpStream::connect(Arc::clone(tcp), vip, port)?;
      let tcp_clone = Arc::clone(tcp);
      let tcp_clone_2 = Arc::clone(tcp);
      let mut stream_clone = stream.clone();
      thread::spawn( move || {
        stream.send_bytes(tcp_clone);
      });
      thread::spawn( move || {
        stream_clone.retransmit(tcp_clone_2);
      });
      Ok(())
    }

    pub fn list_sockets(&self) -> Result<(), TcpError> {
      println!("{:<8} {:<10} {:<8} {:<10} {:<8} {}", 
    "SID", "LAddr", "LPort", "RAddr", "RPort", "Status");

      for (socket_key, socket) in self.socket_table.lock().unwrap().iter() {
          println!(
              "{:<8} {:<10} {:<8} {:<10} {:<8} {}", 
              socket.socket_id, 
              socket_key.local_ip.unwrap_or_else(|| Ipv4Addr::new(0,0,0,0)).to_string(),
              socket_key.local_port.unwrap_or_else(|| 0), 
              socket_key.remote_ip.unwrap_or_else(|| Ipv4Addr::new(0,0,0,0)), 
              socket_key.remote_port.unwrap_or_else(|| 0), 
              socket.status.lock().unwrap().to_string()
          );
      }
      Ok(())
    }

    pub fn send_file(tcp: Arc<Mutex<Self>>, file_path: String, addr: Ipv4Addr, port: u16) -> Result<(), TcpError> {
      // Initiate handshake with connect
      let mut stream = TcpStream::connect(Arc::clone(&tcp), addr, port)?;

      // Open the file
      let file = File::open(&file_path).map_err(|e| TcpError::FileError {
        message: format!("Failed to open file: {}", e)
      })?;

      let mut reader = BufReader::new(file);
      let mut buffer = vec![0; MAX_SEGMENT_SIZE];

      let tcp_clone_2 = Arc::clone(&tcp);
      let tcp_clone_3 = Arc::clone(&tcp);
      let mut stream_clone = stream.clone();
      let mut stream_clone_2 = stream.clone();
      thread::spawn( move || {
        stream_clone.send_bytes(tcp_clone_2);
      });
      thread::spawn( move || {
        stream_clone_2.retransmit(tcp_clone_3);
      });
      
      let mut byte_count = 0;
      // Read and send file contents
      loop {
        match reader.read(&mut buffer) {
          Ok(0) => break, // EOF
          Ok(n) => {
            byte_count += stream.write(&buffer[..n])?;
          },
          Err(e) => return Err(TcpError::FileError {
            message: format!("Error reading file: {}", e)
          }),
        }
      }
      // Close the connection
      let _ = Tcp::close_socket(tcp.clone(), stream.id, true);
      println!("Sent {} bytes from file {}.", byte_count, file_path);
      Ok(())
    }

    pub fn receive_file(tcp: Arc<Mutex<Self>>, file_path: String, port: u16) -> Result<(), TcpError> {
      // Listen for incoming connections (handshake)
      let listener = TcpListener::listen(Arc::clone(&tcp), port)?;
      let socket = listener.accept(Arc::clone(&tcp))?;

      // Might not need this
      if let TcpSocket::Stream(mut stream) = socket.tcp_socket.clone() {
        let tcp_clone_2 = Arc::clone(&tcp);
        thread::spawn( move || {
          stream.send_bytes(tcp_clone_2);
        });
      }

      // Open the destination file
      let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(e) => return Err(TcpError::FileError {
          message: format!("Failed to create file: {}", e)
        }),
      };

      let tcp_socket = socket.tcp_socket;
      let mut byte_count = 0;
      if let TcpSocket::Stream(mut stream) = tcp_socket {
        loop {
          match stream.read(MAX_SEGMENT_SIZE as u32) {
            // how to exit this loop
            Ok(data) => {
              // println!("Read bytes: {}", String::from_utf8_lossy(&data));
              byte_count += file.write(&data).map_err(|e| TcpError::FileError { 
                message: format!("Error writing to file: {}", e) 
              })?;
            },
            Err(e) => {
              if let TcpError::ReadError { message } = e {
                break;
              } else {
                return Err(e);
              }
            }
          }
        }
      }
      println!("Successfully wrote {} bytes into {}.", byte_count, file_path );
      Ok(())
    }

    /* 
      `close_socket` is responsible for checking to see if a socket close can be initiated.
      If there are no more bytes that need to be sent by the stream, the socket can be closed. 
      This function sends a FIN ack to the remote host and sets the socket status to FIN_WAIT_1
     */
    pub fn close_socket(tcp_clone: Arc<Mutex<Self>>, socket_id: u32, is_active: bool) -> Result<(), TcpError> {
      // find the socket by ID
      let mut socket;
      {
        let safe_tcp = tcp_clone.lock().unwrap();
        (_, socket) = safe_tcp.get_socket_by_id(socket_id)
          .ok_or(TcpError::ConnectionError { message: format!("Socket ID {} not recognized.", socket_id) })?;
      }
      // check if the socket is valid and established
      let socket_status;
      {
        socket_status = socket.status.lock().unwrap().clone();
      }
      if is_active && socket_status != SocketStatus::Established && socket_status != SocketStatus::Listening{
        // whatever error here
        return Err(TcpError::ConnectionError { 
          message: format!("Invalid socket status for socket {}: {}", socket.socket_id, socket_status.to_string()) 
        })
      }
      // check if there is still data to send before sending a FIN (block or wait until it is ok to send a FIN)
      // this involves checking the send buffer (UNA == NXT == LBR) and the emptiness of retransmission queue 
      println!("903");
      match socket.tcp_socket {
        TcpSocket::Stream(stream) => {
          let (send_lock, _, send_cv) = &*stream.send_buffer;

          {
            let mut send_buf = send_lock.lock().unwrap();
            // Check if send_buffer or rtq is fully empty.
            let mut can_close = {
              // check if send buffer is empty and retransmission queue is empty
              println!("906: {}, {}", send_buf.is_empty(), stream.rtq.0.lock().unwrap().is_empty());
              send_buf.is_empty() && stream.rtq.0.lock().unwrap().is_empty()
            };
            while !can_close {
              send_buf = send_cv.wait(send_buf).unwrap();
              can_close = {
                // check if send buffer is empty and retransmission queue is empty
                send_buf.is_empty() && stream.rtq.0.lock().unwrap().is_empty()
              };
            }
          }

          let fin_packet;
          {
            let mut status = stream.status.0.lock().unwrap();
            let seq = status.seq_num;
            // set the socket status to FIN_WAIT_1, don't want to upgrade seq or ack for no reason here
            if is_active {
              status.update(Some(SocketStatus::FinWait1), None, None, None);
              *socket.status.lock().unwrap() = SocketStatus::FinWait1;
              println!("920: update to FINWAIT1, sending FIN");
            } else {
              // passive goes from close_wait to last_ack
              status.update(Some(SocketStatus::LastAck), None, None, None);
              *socket.status.lock().unwrap() = SocketStatus::LastAck;
              println!("922: update to LASTACK, sending FIN");
            }
            // create FIN packet
            fin_packet = TcpPacket::new(
              stream.socket_key.local_port.unwrap(),
              stream.socket_key.remote_port.unwrap(),
              status.seq_num,
              status.ack_num,
              TcpFlags::FIN,
              Vec::new(),
            );
          }
          
          let fin_packet_clone = fin_packet.clone();
          {
            // send FIN packet
            let safe_tcp = tcp_clone.lock().unwrap();
            safe_tcp.send_packet(fin_packet, stream.socket_key.remote_ip.unwrap());
          }
          
          // Insert into retransmission queue
          {
            let mut retrans_queue = stream.rtq.0.lock().unwrap();
            retrans_queue.push_back(RTEntry {
                packet: fin_packet_clone,
                timestamp: Instant::now(),
                retries: 0,
            });
          }
          stream.rtq.1.notify_all();
          Ok(())
        },
        TcpSocket::Listener(listener) => {
          
            // Push a unique "close" connection
            let (lock, cvar) = &*listener.incoming_connections;
            {
                let mut conns = lock.lock().unwrap();
                conns.push_back(Connection {
                    socket_key: SocketKey { local_ip: None, local_port: None, remote_ip: None, remote_port: None },
                    seq_num: 0,
                    ack_num: 0,
                    window: 0,
                });
            }
            cvar.notify_all();
            // Remove the listening socket from the socket table
            let socket_key = tcp_clone.lock().unwrap().get_socket_by_id(socket_id).unwrap().0;
            tcp_clone.lock().unwrap().remove_socket(&socket_key);
            println!("Listening socket removed and closed");
            Ok(())
        }
      }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    // SOCKET TABLE FUNCTIONS
    //////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Add a socket to the socket table
    pub fn add_socket(&self, key: SocketKey, socket: Socket) {
        let mut socket_table = self.socket_table.lock().unwrap();
        socket_table.insert(key, socket);
    }

    // Remove a socket from the socket table
    pub fn remove_socket(&self, key: &SocketKey) {
        let mut socket_table = self.socket_table.lock().unwrap();
        socket_table.remove(key);
    }

    // Get a socket from the socket table
    pub fn get_socket(&self, key: SocketKey) -> Option<Socket> {
        let socket_table = self.socket_table.lock().unwrap();
        // First, try to find an exact match
        if let Some(socket) = socket_table.get(&key).cloned() {
            return Some(socket);
        }
        // If no exact match is found, try to find a listening socket with the same port
        if let Some(port) = key.local_port {
            for (k, socket) in socket_table.iter() {
                if k.local_port == Some(port) {
                  let socket_status;
                  {
                    socket_status = socket.status.lock().unwrap().clone();
                  }
                    match socket_status {
                        SocketStatus::Listening => return Some(socket.clone()),
                        _ => continue,
                    }
                }
            }
        }
        // If no match is found, return None
        None
    }

    // Get a socket from the socket 
    pub fn get_socket_by_id(&self, id: u32) -> Option<(SocketKey, Socket)> {
      let table = self.socket_table.lock().unwrap();
      for (socket_key, socket) in table.iter() {
        if socket.socket_id == id {
          return Some((socket_key.clone(), socket.clone()));
        }
      }
      None
    }
    // Get all sockets from the socket table
    pub fn get_all_sockets(&self) -> Vec<Socket> {
        let socket_table = self.socket_table.lock().unwrap();
        socket_table.values().cloned().collect()
    }

    // Search socket table for next unique id
    pub fn next_unique_id(&self) -> u32 {
        let max_id = self.socket_table.lock().unwrap().values().map(|socket| socket.socket_id).max();
        match max_id {
            Some(id) => id + 1,
            None => 0,
        }
    }

    pub fn is_listen(&self, port: u16) -> Option<Socket> {
      if let Ok(socket_table) = self.socket_table.lock() {
        for (socket_key, socket) in socket_table.iter() {
          if let Some(listen_port) = socket_key.local_port {
            let socket_status;
            {
              socket_status = socket.status.lock().unwrap().clone();
            }
            if listen_port == port && socket_status == SocketStatus::Listening {
              return Some(socket.clone());
            }
          }
        }
      }
      return None;
    }
}