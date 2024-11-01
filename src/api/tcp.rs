use std::{net::Ipv4Addr, sync::{mpsc::Receiver, Arc, Mutex, Condvar}};
use std::str::FromStr;
use std::thread;
use super::{packet::{Packet, TcpPacket}, socket::{self, TcpListener, TcpStream}, TCPCommand};

pub struct SocketKey {
    pub local_ip: Option<Ipv4Addr>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: Option<u16>,
}

// initialize tcp struct with a socket table
pub struct Tcp {
    socket_table: Arc<Mutex<std::collections::HashMap<SocketKey, Socket>>>,
}

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

// socket struct definition
pub struct Socket {
    socket_id: u32,
    status: SocketStatus,
    tcp_socket: TcpSocket, 
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
    pub fn new() -> Tcp {
        Tcp {
            socket_table: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /* 
        I'm assuming that there is going to be a tcp protocol handler here as well, similar to how it is in `device.rs`?
        Not really sure if we need to have device being imported? 

        Also need to double check all data types are correct
     */
    pub fn tcp_protocol_handler(device: Arc<Mutex<Tcp>>, receiver: Receiver<TCPCommand>) {
      loop {
          match receiver.recv() {
              Ok(command) => {
                  loop {
                      if let Ok(mut safe_device) = device.try_lock() {
                          match command {
                              TCPCommand::ListenAccept(port) => safe_device.listen_and_accept(&port.parse().unwrap()),
                              TCPCommand::TCPConnect(vip, port) => safe_device.connect(Ipv4Addr::from_str(vip).unwrap(), &port.parse().unwrap()),
                              TCPCommand::ListSockets => safe_device.list_sockets(),
                              TCPCommand::TCPSend(socketId, bytes) => safe_device.send_data(&socketId, &data),
                              TCPCommand::TCPReceive(socketId, numbytes) => safe_device.receive_data(&socketId, &numbytes),
                              TCPCommand::TCPClose(socketId) => safe_device.close_socket(&socketId),
                              TCPCommand::SendFile(path, addr, port) => safe_device.send_file(&path, Ipv4Addr::from_str(addr).unwrap(), &port.parse().unwrap()),
                              TCPCommand::ReceiveFile(path, port) => safe_device.receive_file(&path, &port.parse().unwrap()),
                          }
                          break;
                      }
                  }
              }
              Err(_) => break,
          }
      }
  }

    pub fn listen_and_accept(&self, port: u16) -> ListenerHandle {
        
        let tcp_listener = TcpListener::listen();
        // Search for next unique socket_id
        let socket_id = self.next_unique_id();
        let listening_socket = Socket::new(socket_id, SocketStatus::Listening, TcpSocket::Listener(tcp_listener));
        
        // Insert socket into socket table
        let socket_key = SocketKey {
            local_ip: None,
            local_port: Some(port),
            remote_ip: None,    
            remote_port: None,
        };
        self.add_socket(socket_key, listening_socket);

        let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_signal_clone = Arc::clone(&stop_signal);

        let thread_handle = thread::spawn(move || {
            loop {
                let should_stop = {
                    let (lock, cvar) = &*stop_signal_clone;
                    let mut stop = lock.lock().unwrap();
                    while !*stop {
                        stop = cvar.wait(stop).unwrap();
                    }
                    *stop
                };

                if should_stop {
                    break;
                }

                match tcp_listener.accept() { 
                    Ok(new_socket) => {
                        // insert adding new socket implementation
                    }, 
                    Err(e) => {
                        eprintln!("Error accepting connection: {:?}", e);
                    }
                }
            }
        });

        ListenerHandle {
            port,
            stop_signal,
            thread_handle: Some(thread_handle),
        }
    }

    pub fn stop_listening(&self, handle: &mut ListenerHandle) {
        // Destructure the stop_signal into its Mutex and Condvar components
        let (lock, cvar) = &*handle.stop_signal;
        
        // Acquire the lock on the stop flag
        let mut stop = lock.lock().unwrap();
        
        // Set the stop flag to true
        *stop = true;
        
        // Notify one waiting thread (the listener thread) that the stop flag has changed
        cvar.notify_one();

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
    pub fn receive_packet(&mut self, packet: Packet, src_ip: Ipv4Addr) {
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

            // Check if in socket table
            match self.get_socket(socket_key) {
                Some(socket) => {
                    // handle the socket here
                    
                }
                None => {
                    // handle the error case here
                    // return Err("Socket not found");
                }
            }
    }

    pub fn connect(&self, vip: Ipv4Addr, port: u16) {

    }

    pub fn list_sockets(&self) {

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