use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, Receiver};
use ip_epa127::api::device::Device;
use ip_epa127::api::parser::IPConfig;
use ip_epa127::api::repl::repl;
use ip_epa127::api::packet::Packet;
use ip_epa127::api::tcp::Tcp;
use ip_epa127::api::{CommandType, IPCommand, TCPCommand};
use std::env;
use std::sync::{mpsc, Arc, Mutex};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} --config <lnx-file-path>", args[0]);
        std::process::exit(1);
    }
    let lnx_file_path = &args[2];
    let ip_config: IPConfig = match IPConfig::try_new(lnx_file_path.clone()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1);
        }
    };

    // Ip packets
    let (packet_sender, packet_receiver) = mpsc::channel::<(Packet, Ipv4Addr)>();

    let host = Arc::new(Mutex::new(Device::new(&ip_config, packet_sender)));
    let tcp= Arc::new(Mutex::new(Tcp::new()));

    // Create a channel for communication between the REPL and the Host
    let (repl_send, repl_recv) = mpsc::channel();
    let (ip_send, ip_recv) = mpsc::channel();
    let (tcp_send, tcp_recv) = mpsc::channel();

    let (ip_send_tcp, tcp_recv_ip) = mpsc::channel();
    let (tcp_send_ip, ip_recv_tcp) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
      repl(repl_send).unwrap();
    });
    std::thread::spawn(move || {
      listen_for_commands(ip_send, tcp_send, repl_recv);
    });

    // The Host listens for commands from the REPL
    let host_clone = Arc::clone(&host);
    std::thread::spawn(move ||{
      Device::ip_protocol_handler(host_clone, ip_recv);
    });

    // Method for IP to send a TCP packet
    let host_clone = Arc::clone(&host);
    std::thread::spawn(move || {
      send_tcp_packet(host_clone, ip_recv_tcp);
    });

    // Method for TCP to receive a packet
    let tcp_clone: Arc<Mutex<Tcp>> = Arc::clone(&tcp);
    std::thread::spawn(move || {
      receive_tcp_packet(tcp_clone, tcp_recv_ip);
    });
    
    std::thread::spawn(move ||{
      Tcp::tcp_protocol_handler(tcp_recv, tcp_send_ip);
    });
    
    // In case of tcp, sends the tcp packet to the tcp packet receiver function
    Device::receive_from_interface(host, packet_receiver, Some(ip_send_tcp));
}

pub fn listen_for_commands(ip_send: Sender<IPCommand>, tcp_send: Sender<TCPCommand>, repl_recv: Receiver<CommandType>) {
  loop {
      match repl_recv.recv() {
        Ok(command) => {
          match command {
            CommandType::IP(command) => {
              ip_send.send(command).unwrap();
            },
            CommandType::TCP(command) => {
              tcp_send.send(command).unwrap();
            }
          }
        }
        Err(_) => break,
      }
  }
}

pub fn receive_tcp_packet(tcp_clone: Arc<Mutex<Tcp>>, tcp_recv_ip: Receiver<(Packet, Ipv4Addr)>) {
  loop{
    match tcp_recv_ip.recv() {
      Ok((packet, src_ip)) => {
        loop {
          match tcp_clone.try_lock() {
            Ok(mut safe_tcp) => {
              safe_tcp.receive_packet(packet, src_ip);
              break;
            }
            Err(e) => {}
          }
        }
      },
      Err(e) => {}
    }
  }
}

pub fn send_tcp_packet(host_clone: Arc<Mutex<Device>>, ip_recv_tcp: Receiver<>) {
  loop{
    match tcp_recv_ip.recv() {
      Ok((packet, src_ip)) => {
        loop {
          match host_clone.try_lock() {
            Ok(mut safe_host) => {
              // Look up the next hop in the routing table
              match safe_host.routing_table.lookup(packet.dest_ip) {
                Some(route) => {
                // Forward the packet using the next hop from the route
                  safe_host.forward_packet(packet, route.next_hop.clone());
                },
                None => {
                  eprintln!("No route found for destination IP: {}", packet.dest_ip);
                }
              }
              break;
            }
            Err(e) => {}
          }
        }
      },
      Err(e) => {
        eprintln!("Error receiving TCP packet: {:?}", e);

      }
    }
  }
}