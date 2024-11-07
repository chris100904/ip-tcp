use std::{collections::{HashMap, HashSet}, net::Ipv4Addr, sync::{mpsc::{Receiver, Sender}, Arc, Condvar, Mutex}};
use std::thread;
use rand::Rng;

use super::{packet::{Packet, TcpFlags, TcpPacket}, socket::{self, Connection, TcpListener, TcpStream}, TCPCommand};

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
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
    pub used_ports: Arc<Mutex<HashSet<u16>>>
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
    pub status: SocketStatus,
    pub tcp_socket: TcpSocket, 
}

impl Socket {
    pub fn new(socket_id: u32, status: SocketStatus, tcp_socket: TcpSocket) -> Socket {
        Socket {
            socket_id,
            status, 
            tcp_socket
        }
    }
}

impl Tcp {
    pub fn new(tcp_send_ip: Sender<(TcpPacket, Ipv4Addr)>, src_ip: Ipv4Addr) -> Tcp {
        Tcp {
          src_ip,
          tcp_send_ip,
          socket_table: Arc::new(Mutex::new(std::collections::HashMap::new())),
          used_ports: Arc::new(Mutex::new(HashSet::<u16>::new()))
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
                  match command {
                      TCPCommand::ListenAccept(port) => Tcp::listen_and_accept(tcp_clone, port),
                      TCPCommand::TCPConnect(vip, port) => Tcp::connect(&tcp, vip.parse().unwrap(), port.parse().unwrap()),
                      TCPCommand::ListSockets => {
                        if let Ok(safe_tcp) = tcp.lock() {
                          safe_tcp.list_sockets();
                        }
                      }
                      ,
                      TCPCommand::TCPSend(socket_id, bytes) => {},// safe_tcp.send_data(&socketId, &data),
                      TCPCommand::TCPReceive(socket_id, numbytes) => {},// safe_tcp.receive_data(&socketId, &numbytes),
                      TCPCommand::TCPClose(socket_id) => {},// safe_tcp.close_socket(&socketId),
                      TCPCommand::SendFile(path, addr, port) => {},// safe_tcp.send_file(&path, Ipv4Addr::from_str(addr).unwrap(), &port.parse().unwrap()),
                      TCPCommand::ReceiveFile(path, port) => {},// safe_tcp.receive_file(&path, &port.parse().unwrap()),
                  }
              }
              Err(_) => break,
          }
      }
  }

    pub fn listen_and_accept(tcp: Arc<Mutex<Self>>, port: u16) { // -> ListenerHandle {
        let tcp_listener = TcpListener::listen(Arc::clone(&tcp), port).unwrap();
        
        let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_signal_clone = Arc::clone(&stop_signal);

        let mut tcp_clone = Arc::clone(&tcp);
        let thread_handle = thread::spawn(move || {
            loop {
              let should_stop = {
                    let (lock, cvar) = &*stop_signal_clone;
                    let mut stop = lock.lock().unwrap();
                    // while !*stop {
                    //     stop = cvar.wait(stop).unwrap();
                    // }
                    *stop
                };

                if should_stop {
                    // Remove entry from table?
                    // Stop protocol?
                    break;
                }
                tcp_listener.accept(Arc::clone(&tcp_clone));
              
                // match tcp_listener.accept(self) { 
                //     Ok(new_socket) => {
                //         // insert adding new socket implementation
                //     }, 
                //     Err(e) => {
                //         eprintln!("Error accepting connection: {:?}", e);
                //     }
                // }
            }
        });

        // ListenerHandle {
        //     port,
        //     stop_signal,
        //     thread_handle: Some(thread_handle),
        // }
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
        self.remove_socket(socket_key);
    }

    // Receive a packet
    pub fn receive_packet(&mut self, packet: Packet, src_ip: Ipv4Addr) -> Result<(), String> {
      let src_ip = packet.src_ip;
      let dest_ip = packet.dest_ip;
      let tcp_packet = TcpPacket::parse_tcp(&packet.payload).unwrap();
      // NOTE: src_ip and dest_ip and ports are FLIPPED because we want to check if the dest_ip is our source_ip, etc. 
      let socket_key = SocketKey {
        local_ip: Some(dest_ip),
        local_port: Some(tcp_packet.dest_port),
        remote_ip: Some(src_ip),
        remote_port: Some(tcp_packet.src_port),
      };

      println!("{:?}", tcp_packet.flags);
      match tcp_packet.flags {
        flag if flag == TcpFlags::SYN => {
          // Check if tcp_packet.dst_port is a LISTEN port (src_port in socket table)
          if let Some(listen_socket) = self.is_listen(tcp_packet.dest_port) {
            Ok(if let TcpSocket::Listener(ref listen_conn) = listen_socket.tcp_socket {
              // Acquire lock to check for existing connection
              let already_exists = {
                  let incoming_connections = listen_conn.incoming_connections.0.lock().unwrap();
                  incoming_connections.iter().any(|conn| conn.socket_key == socket_key)
              }; // Lock is released here as `incoming_connections` goes out of scope
              
              if !already_exists {
                  // Add connection if not already present
                  let connection = Connection {
                      socket_key,
                      seq_num: tcp_packet.seq_num,
                      ack_num: tcp_packet.ack_num,
                  };
                  println!("{:?}", (tcp_packet.ack_num, tcp_packet.seq_num));
                  listen_conn.add_connection(connection); // Safe to call `add_connection` here
              }
            })
          } else {
            // If not, drop the packet.
            return Err("No listening socket found".to_string());
          }
        },
        flag if flag == TcpFlags::SYN | TcpFlags::ACK => {
          // Check if connection is already in the socket table and has status SYN-SENT
          Ok(if let Some(socket) = self.get_socket(socket_key) {
            if socket.status == SocketStatus::SynSent {
              // If so, then proceed with connect (send the ACK) and establish the connection
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                *lock.lock().unwrap() = (SocketStatus::Established, tcp_packet.seq_num, tcp_packet.ack_num);

                // Notify waiting threads that a new connection is available
                cvar.notify_all(); // changed one to all
              } else {
                return Err("Invalid socket status".to_string());
              }
            } else {
              return Err("No socket found".to_string());
            }
          })
          // If not, drop the packet.
        },
        flag if flag == TcpFlags::ACK => {
          // Check if connection is already in the socket table and has status SYN-RECEIVED
          Ok(if let Some(socket) = self.get_socket(socket_key) {
            if socket.status == SocketStatus::SynReceived {
              // If so, then finish accept() and establish the connection
              if let TcpSocket::Stream(stream) = socket.tcp_socket {
                let (lock, cvar) = &*stream.status;
                {
                  *lock.lock().unwrap() = (SocketStatus::Established, tcp_packet.seq_num, tcp_packet.ack_num);
                }
                // Notify waiting threads that a new connection is available
                cvar.notify_all(); // changed one to all
              } else {
                return Err("Invalid socket status".to_string());
              }
            } 
            // Other valid statuses: FIN-WAIT1, CLOSING, LAST-ACK
            else if socket.status == SocketStatus::FinWait1 {
              todo!()
            } else if socket.status == SocketStatus::Closing {
              todo!()
            } else if socket.status == SocketStatus::LastAck {
              todo!()
            } else {
              // If not, drop the packet.
              return Err("No socket found".to_string());
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
          todo!()
        },
        flag if flag == TcpFlags::FIN | TcpFlags::ACK => {
          // Check if connection is already in the socket table
          // Valid statuses: FIN-WAIT1
          todo!()
        },
        _ => {
          // Drop the packet
          return Err("Dropped packet with unknown flags".to_string());
        }
      }
    }

    pub fn is_listen(&self, port: u16) -> Option<Socket> {
      if let Ok(socket_table) = self.socket_table.lock() {
        for (socket_key, socket) in socket_table.iter() {
          if let Some(listen_port) = socket_key.local_port {
            if listen_port == port && socket.status == SocketStatus::Listening {
              return Some(socket.clone());
            }
          }
        }
      }
      return None;
    }

    pub fn send_packet(&self, packet: TcpPacket, dst_ip: Ipv4Addr) {
      self.tcp_send_ip.send((packet, dst_ip));
    }

    pub fn gen_rand_u32() -> u32 {
      let mut rng = rand::thread_rng();
      return rng.gen();
    }

    // Generates random available port number using the used_ports hashset. Does NOT insert into the hashset.
    pub fn get_port(&self) -> u16 {
      loop {
        let mut rng = rand::thread_rng();
        let port = rng.gen_range(20_000..=u16::MAX);
        loop {
          if let Ok(used_ports) = self.used_ports.try_lock() {
            if !used_ports.contains(&port) {
              return port;
            }
            break;
          }
        }
      }
    }

    pub fn connect(tcp: &Arc<Mutex<Self>>, vip: Ipv4Addr, port: u16) {
      // Create new normal socket
      let client_conn = TcpStream::connect(Arc::clone(tcp), vip, port).expect("oops");
    }

    pub fn list_sockets(&self) {
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
              socket.status.to_string()
          );
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
    pub fn remove_socket(&self, key: SocketKey) {
        let mut socket_table = self.socket_table.lock().unwrap();
        socket_table.remove(&key);
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
                    match socket.status {
                        SocketStatus::Listening => return Some(socket.clone()),
                        _ => continue,
                    }
                }
            }
        }
        // If no match is found, return None
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
}