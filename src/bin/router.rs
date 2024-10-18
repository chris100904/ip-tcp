use std::net::Ipv4Addr;
use crate::network::{Packet, RoutingTable};
use crate::link::NetworkInterface;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use ip_epa127::api::repl::repl;
use ip_epa127::api::{Command, InterfaceState};

pub struct Router {
    pub interfaces: Vec<InterfaceConfig>,
    pub neighbors: Vec<NeighborConfig>,
    pub routing_mode: RoutingType,
    pub static_routes: Vec<StaticRoute>, // should be empty?
    pub rip_neighbors: Option<Vec<Ipv4Addr>>,
    pub rip_periodic_update_rate: Option<u64>,
    pub rip_timeout_threshold: Option<u64>, 

    // routing table 
    pub routing_table: RoutingTable,
}

impl Router {
    // TODO: intiialize the interface as part of the Host
    pub fn new(ip_config: &IPConfig) -> Host {
        let mut routing_table = RoutingTable::new(ip_config);
        Router { 
            interfaces: ip_config.interfaces, // Assume that lnx is properly formatted
            neighbors: ip_config.neighbors, routing_mode:
            ip_config.routing_mode, 
            static_routes: ip_config.static_routes,
            rip_neighbors: ip_config.rip_neighbors,
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

    pub fn list_interfaces(&self) {
        println!("Name  Addr/Prefix State");
        
        for ifstate in &self.interfaces {
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

        self.forward_packet(&packet, dest_ip).unwrap();
        // self.socket.send_to(&packet.to_bytes(), 0).unwrap();
    }

    pub fn add_interface(&mut self, interface: NetworkInterface) {
        self.interfaces.push(interface);
    }    

    // should the routing table have pointer to interface? 
    // each node does, so yes
    pub fn add_route(&mut self, destination: Ipv4Addr, prefix_length: usize, interface: NetworkInterface) {    
        self.routing_table.insert(destination, prefix_length).unwrap();
    }

    pub fn remove_route(&mut self, destination: Ipv4Addr, prefix_length: usize) {
        self.routing_table.remove(destination, prefix_length).unwrap();
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

        // send the packet to the interface
        interface.send_data(destination_ip, packet)?;
        Ok(())
    }

    // return error as well? 
    pub fn handle_received_packet(&self, interface: &NetworkInterface, raw_packet: &[u8]) {
        match Packet::parse_ip_packet(raw_packet) {
            Ok(packet) => {
                if packet.is_local() {
                    self.process_local_packet(packet);
                } else {
                    self.forward_packet(packet);
                }
            },
            Err(err) => {
                eprintln!("Failed to parse received packet: {}", err);
            },
        }
    }

    // process local packets
    fn process_local_packet(&self, packet: Packet) {
        println!("Received local packet from {}: {}", packet.src_ip, packet.data);
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
    let mut ip_config: IPConfig = match parser::try_new(lnx_file_path) {
        Ok(config) => config, 
        Err(e) => {
            eprintln!("Failed to parse the lnx file: {}", e);
            std::process::exit(1); 
        }
    };
    parser::parse(&ip_config);
    
    // get all necessary things and pass it into new
    let mut router = Router::new(&ip_config);

    // Create a channel for communication between the REPL and the Host
    let (tx, rx) = mpsc::channel();

    // Spawn the REPL in a separate thread
    std::thread::spawn(move || {
        repl(tx).unwrap();
    });

    // The Host listens for commands from the REPL
    router.listen_for_commands(rx);
}