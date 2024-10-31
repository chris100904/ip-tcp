use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, Receiver};
use ip_epa127::api::device::Device;
use ip_epa127::api::parser::IPConfig;
use ip_epa127::api::repl::repl;
use ip_epa127::api::packet::Packet;
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
    let (packet_sender, packet_receiver) = mpsc::channel::<(Packet, Ipv4Addr)>();

    let host = Arc::new(Mutex::new(Device::new(&ip_config, packet_sender)));

    // Create a channel for communication between the REPL and the Host
    let (repl_send, repl_recv) = mpsc::channel();
    let (ip_send, ip_recv) = mpsc::channel();
    let (tcp_send, tcp_recv) = mpsc::channel();

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
    
    Device::receive_from_interface(host, packet_receiver);
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