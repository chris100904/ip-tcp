use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use ip_epa127::api::network_interface::{self, NetworkInterface};
use ip_epa127::api::repl::repl;
use ip_epa127::api::packet::Packet;
use ip_epa127::api::routing_table::{Table, NextHop};
use ip_epa127::api::{Command, InterfaceStruct};
use ip_epa127::api::parser::{IPConfig, InterfaceConfig, NeighborConfig, RoutingType, StaticRoute};

pub struct Router {
    pub interfaces: Vec<InterfaceStruct>,
    pub neighbors: Vec<NeighborConfig>,
    pub routing_mode: RoutingType,
    pub static_routes: Vec<StaticRoute>, // should be empty?
    pub rip_neighbors: Option<Vec<Ipv4Addr>>,
    pub rip_periodic_update_rate: Option<u64>,
    pub rip_timeout_threshold: Option<u64>, 

    // routing table 
    pub routing_table: Table,
}

impl Router {
    // TODO: intiialize the interface as part of the Host
    pub fn new(ip_config: &IPConfig, packet_sender: Sender<Vec<u8>>) -> Router {
        let mut routing_table = Table::new(ip_config);
        let mut ifstructs: Vec<InterfaceStruct> = Vec::new();
        for interface in ip_config.interfaces.clone() {
            ifstructs.push(InterfaceStruct::new(interface, packet_sender.clone()));
        }
        
        Router { 
            interfaces: ifstructs, // Assume that lnx is properly formatted
            neighbors: ip_config.neighbors.clone(), 
            routing_mode: ip_config.routing_mode.clone(), 
            static_routes: ip_config.static_routes.clone(),
            rip_neighbors: ip_config.rip_neighbors.clone(),
            rip_periodic_update_rate: ip_config.rip_periodic_update_rate,
            rip_timeout_threshold: ip_config.rip_timeout_threshold,
            routing_table,
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

    pub fn receive_from_interface(&mut self, receiver: Receiver<Vec<u8>>) {
        loop {
            match receiver.recv() {
                Ok(packet) => {
                    todo!();
                    // self.process_packet(&packet);
                }
                Err(_) => break,
            }
        }
    }

    pub fn list_interfaces(&self) {
        println!("Name  Addr/Prefix State");
        
        for interface in &self.interfaces {
            println!("{}  {:<15} {}", 
                interface.config.name, 
                format!("{}/{}", 
                    interface.config.assigned_ip, 
                    interface.config.assigned_prefix.prefix_len()), 
                if interface.enabled {"up"} else {"down"});
        }
    }

    pub fn list_neighbors(&self) {
        println!("Iface VIP  UDPAddr");
        for interface in &self.interfaces {
            if interface.enabled {
                for neighbor in &self.neighbors {
                    if neighbor.interface_name == interface.config.name {
                        println!("{}     {}     {}", interface.config.name, neighbor.dest_addr, 
                            neighbor.udp_addr.to_string() + ":" + &neighbor.udp_port.to_string());
                    }
                }
            }
        }
    }

    pub fn list_routes(&self) {
        println!("T       Prefix   Next hop   Cost");
        for route in &self.routing_table.get_routes() {
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
        for ifstruct in &mut self.interfaces {
            if ifstruct.config.name == ifname {
                ifstruct.enabled = false;
                break;
            }
        }
    }

    pub fn enable_interface(&mut self, ifname: &str) {
        for ifstruct in &mut self.interfaces {
            if ifstruct.config.name == ifname {
                ifstruct.enabled = true;
                break;
            }
        }
    }

    pub fn send_test_packet(&self, addr: &str, message: &str) {
        let dest_ip = Ipv4Addr::from_str(addr).unwrap();
        let data = message.as_bytes();
        // let packet = Packet::new(self.ip_addr, dest_ip, 17, data.to_vec());

        // self.forward_packet(&packet, dest_ip).unwrap();
        // self.socket.send_to(&packet.to_bytes(), 0).unwrap();

        todo!()
    }

    pub fn add_interface(&mut self, interface: NetworkInterface) {
        todo!()
    }

    // should the routing table have pointer to interface? 
    // each node does, so yes
    pub fn add_route(&mut self, destination: Ipv4Addr, prefix_length: usize, interface: NetworkInterface) {    
        // self.routing_table.insert(destination, prefix_length).unwrap();
        todo!()
    }

    pub fn remove_route(&mut self, destination: Ipv4Addr, prefix_length: usize) {
        // self.routing_table.remove(destination, prefix_length).unwrap();
        todo!()
    }

    // pub fn lookup_route(&self, destination: Ipv4Addr) -> Option<NetworkInterface> {
    //     self.routing_table.lookup(destination)
    // }

    pub fn forward_packet(&self, packet: &Packet, destination_ip: Ipv4Addr) -> Result<(), std::io::Error> {
        // lookup the route for the destination IP
        let interface = match self.routing_table.lookup(destination_ip) {
            Some(interface) => interface,
            None => {
                // the packet should also be dropped, however that needs to be implemented
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No route found for destination IP: {}", destination_ip),
                ));
            },
        };

        todo!();
        // send the packet to the interface
        //interface.send_data(destination_ip, packet)?;
        Ok(())
    }

    // return error as well? 
    pub fn handle_received_packet(&self, interface: &NetworkInterface, packet: Packet) {
        let mut is_local = false;

        // Iterate through all the interfaces to check if the packet is local
        for iface in &self.interfaces {
            if packet.is_local(iface.config.assigned_ip){
                is_local = true;
                break; 
            }
        }

        if is_local {
            self.process_local_packet(packet);
        } else {
            // forward the packet to destination
            self.forward_packet(&packet, packet.dest_ip);
        }
    }

    // process local packets
    fn process_local_packet(&self, packet: Packet) {
        todo!("do something with packet");
        // println!("Received local packet from {}: {}", packet.src_ip, packet.data);
        // TODO: do something with the packet
    }
}

fn main() {
    // use `new` from parse to get the IPConfig
    let args: Vec<String> = env::args().collect();  
    if args.len() < 3 {
        eprintln!("Usage: {} --config <lnx-file-path>", args[0]);
        std::process::exit(1); 
    }
    // use the IPConfig and pass into `parse`, the return should be the updated IPConfig
    let lnx_file_path = &args[2];
    let mut ip_config: IPConfig = match IPConfig::try_new(lnx_file_path.clone()) {
        Ok(config) => config, 
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1); 
        }
    };
    
    let (packet_sender, packet_receiver) = mpsc::channel::<Vec<u8>>();

    // get all necessary things and pass it into new
    let mut router = Router::new(&ip_config, packet_sender);

    // Create a channel for communication between the REPL and the Host
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    router.listen_for_commands(rx);

    router.receive_from_interface(packet_receiver);
}