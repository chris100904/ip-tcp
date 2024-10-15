use std::net::Ipv4Addr;
use crate::network::{Packet, RoutingTrie};
use crate::link::NetworkInterface;


pub struct Router {
    interfaces: Vec<NetworkInterface>,
    routing_table: RoutingTrie,
    ip_addr: Ipv4Addr,
}

impl Router {
    pub fn new(ip_addr: Ipv4Addr) -> Router {
        Router {
            interfaces: Vec::new(),
            routing_table: RoutingTrie::new(),
            ip_addr
        }
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
    
}