use ip_epa127::api::network_interface::NetworkInterface;
use ip_epa127::api::parser::{self, IPConfig, InterfaceConfig, RoutingType, NeighborConfig, StaticRoute};
use ip_epa127::api::repl::repl;
use ip_epa127::api::routing_table::{Table, NextHop};
use ip_epa127::api::{Command, InterfaceStruct};
use ip_epa127::api::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::str::FromStr;
use etherparse::{err::ip, Ipv4Header, Ipv4HeaderSlice};
use std::env;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;


// Define the command types that the REPL can send to the Host

#[derive(Debug)]
pub struct Host {
    pub interface: InterfaceStruct,
    pub neighbors: Vec<NeighborConfig>,
    pub routing_mode: RoutingType,
    pub static_routes: Vec<StaticRoute>,
    pub forwarding_table: Table,
}

impl Host {
    pub fn new(ip_config: &IPConfig, packet_sender: Sender<Packet>) -> Host {
        let interface = InterfaceStruct {
            config: ip_config.interfaces[0].clone(),
            enabled: true,
            interface: NetworkInterface::new(&ip_config.interfaces[0], packet_sender.clone()),
        };

        Host {
            interface,
            neighbors: ip_config.neighbors.clone(),
            routing_mode: ip_config.routing_mode.clone(),
            static_routes: ip_config.static_routes.clone(),
            forwarding_table: Table::new(&ip_config),
        }
    }

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

    pub fn receive_from_interface(&mut self, receiver: Receiver<Packet>) {
        loop {
            match receiver.recv() {
                Ok(packet) => {
                    // todo!();
                    self.process_packet(packet);
                }
                Err(_) => break,
            }
        }
    }

    pub fn list_interfaces(&self) {
        println!("Name  Addr/Prefix State");
        let interface = &self.interface;
        println!("{}  {:<15} {}", interface.config.name, 
            format!("{}/{}", interface.config.assigned_ip, 
                interface.config.assigned_prefix.prefix_len()), 
            if interface.enabled {"up"} else {"down"});
    }

    pub fn list_neighbors(&self) {
        println!("Iface VIP  UDPAddr");
        if self.interface.enabled {
            for neighbor in &self.neighbors {
                // REMOVED: to check that we are connecting the right interfaces together
                println!("{}     {}     {}", neighbor.interface_name, neighbor.dest_addr, neighbor.udp_addr.to_string() + ":" + &neighbor.udp_port.to_string());
            }
        }
    }

    pub fn list_routes(&self) {
        println!("T       Prefix   Next hop   Cost");
        for route in &self.forwarding_table.get_routes() {
            let routing_type = match route.routing_mode {
                RoutingType::None => "L".to_string(),
                RoutingType::Static => "S".to_string(),
                RoutingType::Rip => "R".to_string()
            };
            let prefix = route.prefix.to_string();
            let next_hop: String = match &route.next_hop {
                NextHop::Interface(interface) => {
                    format!("LOCAL:{}", interface.name).to_string()
                },
                NextHop::IPAddress(ip_addr) => {
                    ip_addr.to_string()
                }
            };
            let cost = match route.cost{
                Some(cost) => cost.to_string(),
                None => "-".to_string()
            };
            println!("{}       {}   {}   {}", routing_type, prefix, next_hop, cost);
        }
    }

    pub fn disable_interface(&mut self, ifname: &str) {
        if &self.interface.config.name == ifname {
            self.interface.enabled = false;
        }
    }

    pub fn enable_interface(&mut self, ifname: &str) {
        if &self.interface.config.name == ifname {
            self.interface.enabled = true;
        }
    }

    pub fn send_test_packet(&self, addr: &str, message: &str) {
        let dest_ip = Ipv4Addr::from_str(addr).unwrap();
        let data = message.as_bytes();
        let packet = Packet::new(self.interface.config.assigned_ip, dest_ip, 0, data.to_vec());
        
        match self.forwarding_table.lookup(dest_ip) {
            Some(interface) => {
                
                // interface.send_data(packet).unwrap();
                todo!();

                println!("Sent {} bytes", data.len());
            }
            None => {
                eprintln!("Error: No valid interface found for destination IP: {}", dest_ip);
            }
        }
    }

    // // TODO: Probably delete this
    // pub fn receive_packet(&mut self) {
    //     let mut buf = [0; 1500];
    //     match self.socket.recv_from(&mut buf) {
    //         Ok((size, _)) => {
    //             self.process_packet(&buf[..size]);
    //         }
    //         Err(e) => {
    //             eprintln!("Error receiving packet: {}", e);
    //         }
    //     }
    // }

    // // TODO: IP FORWARDING
    // pub fn process_local_packet(&mut self, packet: Packet) {
    //     if let Some(neighbor) = self.neighbors.iter().find(|n| n.dest_addr == packet.src_ip) {
    //         // Send the packet to the UDP port of the neighbor
    //         let udp_addr = neighbor.udp_addr;
    //         let udp_port = neighbor.udp_port;

    //         todo!();
    //         // Assuming you have a method to send data to a specific UDP address
    //         // let result = self.interface.interface.send_data(udp_addr, packet.to_bytes());

    //         // match result {
    //         //     Ok(_) => println!("Sent packet to {}:{}", udp_addr, udp_port),
    //         //     Err(e) => eprintln!("Failed to send packet: {}", e),
    //         // }
    //     } else {
    //         eprintln!("No neighbor found for source IP: {}", packet.src_ip);
    //     }
    // }

    /* If a Host receives a packet, that means that the packet has reached a destination. 
       Hosts are endpoints in the network, so we can just terminate and print here. */
    pub fn process_packet(&mut self, packet: Packet) {
        println!("Received test packet: Src: {}, Dst: {}, TTL:  {}, Data:  {}", 
            packet.src_ip, packet.dest_ip, packet.ttl, String::from_utf8(packet.payload).unwrap());
    }
}

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
    let (packet_sender, packet_receiver) = mpsc::channel::<Packet>();

    let mut host = Host::new(&ip_config, packet_sender);

    // Create a channel for communication between the REPL and the Host
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    host.listen_for_commands(rx);

    host.receive_from_interface(packet_receiver);
}