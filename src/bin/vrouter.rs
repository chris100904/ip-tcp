use std::sync::mpsc::{Receiver, Sender};
use std::{env, thread};
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use ip_epa127::api::device::Device;
use ip_epa127::api::repl::repl;
use ip_epa127::api::packet::Packet;
use ip_epa127::api::parser::IPConfig;
use ip_epa127::api::{CommandType, IPCommand};

fn main() {
    // use `new` from parse to get the IPConfig
    let args: Vec<String> = env::args().collect();  
    if args.len() < 3 {
        eprintln!("Usage: {} --config <lnx-file-path>", args[0]);
        std::process::exit(1); 
    }
    // use the IPConfig and pass into `parse`, the return should be the updated IPConfig
    let lnx_file_path = &args[2];
    let ip_config: IPConfig = match IPConfig::try_new(lnx_file_path.clone()) {
        Ok(config) => config, 
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1); 
        }
    };
    
    let (packet_sender, packet_receiver) = mpsc::channel::<(Packet, Ipv4Addr)>();

    // get all necessary things and pass it into new
    let router = Arc::new(Mutex::new(Device::new(&ip_config, packet_sender)));

    // Create a channel for communication between the REPL and the Host
    let (repl_send, repl_recv) = mpsc::channel();
    let (ip_send, ip_recv) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
      repl(repl_send).unwrap();
    });

    std::thread::spawn(move || {
      listen_for_commands(ip_send, repl_recv);
    });

    let router_clone = Arc::clone(&router);
    thread::spawn(move ||{
        Device::ip_protocol_handler(router_clone, ip_recv);
    });
    // send a rip request to all neighbors at the start
    
    // start the periodic updates
    let router_clone_2 = Arc::clone(&router);
    thread::spawn(move || { 
      Device::start_periodic_updates(router_clone_2);
    });
    
    Device::receive_from_interface(router, packet_receiver, None);
}

pub fn listen_for_commands(ip_send: Sender<IPCommand>, repl_recv: Receiver<CommandType>) {
  loop {
      match repl_recv.recv() {
        Ok(command) => {
          match command {
            CommandType::IP(command) => {
              ip_send.send(command).unwrap();
            },
            CommandType::TCP(_) => {}
          }
        }
        Err(_) => break,
      }
  }
}