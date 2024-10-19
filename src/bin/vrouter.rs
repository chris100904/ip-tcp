use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex, RwLock};
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
    pub fn new(ip_config: &IPConfig, packet_sender: Sender<Packet>) -> Router {
        let routing_table = Table::new(ip_config);
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

    pub fn listen_for_commands(router: Arc<Mutex<Router>>, receiver: Receiver<Command>) {
        loop {
            match receiver.recv() {
                Ok(command) => {
                    loop {
                        if let Ok(mut safe_router) = router.try_lock() {
                            match command {
                                Command::ListInterfaces => safe_router.list_interfaces(),
                                Command::ListNeighbors => safe_router.list_neighbors(),
                                Command::ListRoutes => safe_router.list_routes(),
                                Command::DisableInterface(ifname) => safe_router.disable_interface(&ifname),
                                Command::EnableInterface(ifname) => safe_router.enable_interface(&ifname),
                                Command::SendTestPacket(addr, msg) => safe_router.send_test_packet(&addr, &msg),
                                Command::Exit => break,
                            }
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }

    pub fn receive_from_interface(router: Arc<Mutex<Router>>, receiver: Receiver<Packet>) {
        loop {
            match receiver.recv() {
                Ok(packet) => {
                    // todo!();
                    loop {
                        if let Ok(mut safe_router) = router.try_lock() {
                            // println!("HELLO");
                            safe_router.process_packet(packet);
                            break;
                        }
                    }
                }
                Err(e) => eprintln!("ERROR!: {e}"),
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

    pub fn send_test_packet(& mut self, addr: &str, message: &str) {
        let dest_ip = Ipv4Addr::from_str(addr).unwrap();
        let data = message.as_bytes();
        // the source ip is assumed to be one of the interfaces assigned ips? 
        let packet = Packet::new(self.interfaces[0].config.assigned_ip, dest_ip, 0, data.to_vec());

        if self.is_packet_for_router(&dest_ip) {
            self.process_local_packet(packet);
        } else {
            match self.routing_table.lookup(dest_ip) {
                Some(route) => {
                    self.forward_packet(packet, route.next_hop.clone()); // Forward the packet using forward_packet logic
                }
                None => {
                    eprintln!("Error: No valid route found for destination IP: {}", dest_ip);
                }
            }
        }
    }

    // Forward a packet to the next hop (another router or destination)
    pub fn forward_packet(&self, packet: Packet, mut next_hop: NextHop) {
        loop {
            match next_hop {
                NextHop::Interface(interface) => {
                    println!("INTERFACE: {:?}", interface);
                    if let Some(matching_interface_struct) = self.find_interface_by_name(&interface.name) {
                        // iterate through neighbors to find matching neighbor's interface's port
                        if let Some((neighbor_addr, neighbor_port)) = self.find_neighbor_socket(&matching_interface_struct) {
                            // Send the packet along with the neighbor's port number
                            matching_interface_struct.interface.send_packet(packet, neighbor_addr, neighbor_port);
                            return; // Exit after sending the packet
                        } else {
                            eprintln!("Error: Neighbor interface not found for: {}", interface.name);
                            return; // Exit if no matching neighbor interface is found
                        }
                    } else {
                        eprintln!("Error: Interface not found: {}", interface.name);
                        return;
                    }
                }
                NextHop::IPAddress(ip_addr) => {
                    /*
                        Logic behind this is that it should eventually terminate by finding
                        a proper interface to send through. If it never does, then we error print.
                     */
                    match self.routing_table.lookup(ip_addr) {
                        Some(new_route) => {
                            next_hop = new_route.next_hop.clone();
                        }
                        None => {
                            eprintln!("Error: No valid interface found for destination IP: {}", ip_addr);
                            return;
                        }
                    }
                }
            }
        }
    }

    pub fn process_packet(&mut self, packet: Packet) {
        // check if the packet dest_ip matches any of the interfaces
        if self.is_packet_for_router(&packet.dest_ip) {
            self.process_local_packet(packet);
        } else {
            // packet is not meant for this router, so we need to forward it
            match self.routing_table.lookup(packet.dest_ip) {
                Some(route) => {
                    println!("ROUTE: {:?}", route);
                    self.forward_packet(packet, route.next_hop.clone());
                }
                None => {
                    eprintln!("Error: No valid interface found for destination IP: {}", packet.dest_ip);
                }
            }
        }
    }

    // Process packets meant for the router (like a host would do)
    pub fn process_local_packet(&mut self, packet: Packet) {
        println!("payload: {:?}", packet.payload);
        println!("Router received a local packet: Src: {}, Dst: {}, TTL: {}, Data: {}", 
            packet.src_ip, packet.dest_ip, packet.ttl, 
            String::from_utf8(packet.payload).unwrap());
    }

    // Helper to check if a packet is for a router (any of the router's interfaces)
    fn is_packet_for_router(&self, dest_ip: &Ipv4Addr) -> bool {
        for interface in &self.interfaces {
            if interface.config.assigned_ip == *dest_ip {
                return true; // This IP matches one of the router's interfaces
            }
        }
        false
    }

    fn find_interface_by_name(&self, interface_name: &str) -> Option<&InterfaceStruct> {
        self.interfaces.iter().find(|interface| interface.config.name == interface_name)
    }
    
    // Helper function to find the port of the neighbor's interface
    fn find_neighbor_socket(&self, matching_interface_struct: &InterfaceStruct) -> Option<(Ipv4Addr, u16)> {
        let interface_name = matching_interface_struct.config.name.clone(); // This should be a field in your struct
    
        // Iterate through the neighbors to find the matching interface based on IP address
        for neighbor in &self.neighbors {
            // Check if the neighbor's IP matches the interface's IP
            if neighbor.interface_name == interface_name {
                return Some((neighbor.udp_addr, neighbor.udp_port)); // Return the port number if a match is found
            }
        }
        None // Return None if no matching neighbor interface is found
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
    let ip_config: IPConfig = match IPConfig::try_new(lnx_file_path.clone()) {
        Ok(config) => config, 
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1); 
        }
    };
    
    let (packet_sender, packet_receiver) = mpsc::channel::<Packet>();

    // get all necessary things and pass it into new
    let router = Arc::new(Mutex::new(Router::new(&ip_config, packet_sender)));

    // Create a channel for communication between the REPL and the Host
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    let router_clone = Arc::clone(&router);
    std::thread::spawn(move ||{
        Router::listen_for_commands(router_clone, rx);
    });
    
    Router::receive_from_interface(router, packet_receiver);
}