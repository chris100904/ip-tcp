use ip_epa127::api::parser::{self, IPConfig};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use etherparse::{err::ip, Ipv4Header, Ipv4HeaderSlice};
use crate::packet::Packet;
use std::env;
use crate::network::{Packet, RoutingTable};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use crate::api::{Command, InterfaceState};


// Define the command types that the REPL can send to the Host

#[derive(Debug)]
pub struct Host {
    pub interface: InterfaceState,
    pub neighbors: Vec<NeighborConfig>,
    pub routing_mode: RoutingType,
    pub static_routes: Vec<StaticRoute>,
    pub forwarding_table: RoutingTable,
}

impl Host {
    pub fn new(ip_config: &IPConfig) -> Host {
        let forwarding_table = RoutingTable::new(&ip_config);
        Host {
            // interface: ip_config.interfaces[0],
            interface: InterfaceState {
                config: ip_config.interfaces[0],
                enabled: true,
            },
            neighbors: ip_config.neighbors,
            routing_mode: ip_config.routing_mode,
            static_routes: ip_config.static_routes,
            forwarding_table,
        }
    }

    // The Host will listen for REPL commands and process them
    pub fn listen_for_commands(&mut self, receiver: Receiver<Command>) {
        loop {
            match receiver.recv() {
                Ok(command) => {
                    match command {
                        Command::ListInterfaces => self.list_interfaces(),
                        Command::ListNeighbors => self.list_neighbors(),
                        Command::ListRoutes => self.list_routes(),
                        Command::DisableInterface(ifname) => self.disable_interface(&ifname),
                        Command::EnableInterface(ifname) => self.enable_interface(&ifname),
                        Command::SendTestPacket(addr, msg) => self.send_test_packet(&addr, &msg),
                        Command::Exit => break,
                    }
                }
                Err(_) => break,
            }
        }
    }

    pub fn list_interfaces(&self) {
        println!("Name  Addr/Prefix State");
        
        for ifstate in &self.interface {
            println!("{}  {:<15} {}", ifstate.config.name, format!("{}/{}", ifstate.config.assigned_ip, ifstate.config.assigned_prefix.prefix_len()), if ifstate.enabled {"up"} else {"down"});
        }
    }

    pub fn list_neighbors(&self) {
        println!("Iface VIP  UDPAddr");
        for ifstate in &self.interface {
            if ifstate.enabled {
                for neighbor in &self.neighbors {
                    // to check that we are connecting the right interfaces together
                    if neighbor.interface_name == ifstate.config.name {
                        println!("{}     {}     {}", ifstate.config.name, neighbor.dest_addr, neighbor.udp_addr.to_string() + ":" + &neighbor.udp_port.to_string());
                    }
                }
            }
        }
    }

    pub fn list_routes(&self) {
        println!("T       Prefix   Next hop   Cost");
        for route in &self.forwarding_table.routes {
            match route.next_hop {
                InterfaceConfig::Local { ifname, prefix } => {
                    println!("L  {:<15}  LOCAL:{}     0", format!("{}/{}", prefix.addr(), prefix.prefix_len()), ifname);
                }
                InterfaceConfig::Rip { next_hop, cost, prefix } => {
                    println!("R  {:<15}  {}     {}", format!("{}/{}", prefix.addr(), prefix.prefix_len()), next_hop, cost);
                }
                InterfaceConfig::Static { next_hop, prefix } => {
                    println!("S  {:<15}  {}     -", format!("{}/{}", prefix.addr(), prefix.prefix_len()), next_hop);
                }
            }
        }
    }

    pub fn disable_interface(&mut self, ifname: &str) {
        for ifstate in &mut self.interface {
            if ifstate.config.name == ifname {
                ifstate.enabled = false;
                break;
            }
        }
    }

    pub fn enable_interface(&self, ifname: &str) {
        for ifstate in &mut self.interface {
            if ifstate.config.name == ifname {
                ifstate.enabled = true;
                break;
            }
        }
    }

    pub fn send_test_packet(&self, addr: &str, message: &str) {
        let dest_ip = Ipv4Addr::from_str(addr).unwrap();
        let data = message.as_bytes();
        let packet = Packet::new(self.ip_addr, IpAddr::V4(dest_ip), 17, data.to_vec());
        self.socket.send_to(&packet.to_bytes(), 0).unwrap();
    }

    // TODO: Probably delete this
    pub fn receive_packet(&mut self) {
        let mut buf = [0; 1500];
        match self.socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                self.process_packet(&buf[..size]);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }

    // TODO: IP FORWARDING
    pub fn process_local_packet(&mut self, packet: Packet) {
        
    }


    // TODO: Update this (should be called when we receive packet down to up from the interface)
    pub fn process_packet(&mut self, raw_data: &[u8]) {
        if let Ok(packet) = Packet::parse_ip_packet(raw_data) {
            println!("Received packet from {}: {:?}", packet.src_ip, packet);
            // Handle the packet
        }
        // local? 

        // not local
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} --config <lnx-file-path>", args[0]);
        std::process::exit(1);
    }
    let lnx_file_path = &args[2];
    let mut ip_config: IPConfig = match parser::try_new(lnx_file_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1);
        }
    };
    parser::parse(&ip_config);

    let mut host = Host::new(&ip_config);

    // Create a channel for communication between the REPL and the Host
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    host.listen_for_commands(rx);
}