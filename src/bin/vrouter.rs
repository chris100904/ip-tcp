use std::env;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use ip_epa127::api::device::Device;
use ip_epa127::api::repl::repl;
use ip_epa127::api::packet::Packet;
use ip_epa127::api::parser::IPConfig;

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
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    let router_clone = Arc::clone(&router);
    std::thread::spawn(move ||{
        Device::listen_for_commands(router_clone, rx);
    });
    // send a rip request to all neighbors at the start

    // start the periodic updates
    Device::start_periodic_updates(Arc::clone(&device));
    Device::receive_from_interface(router, packet_receiver);
}