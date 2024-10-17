use ip_epa127::api::parser::{self, IPConfig};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use etherparse::{err::ip, Ipv4Header, Ipv4HeaderSlice};
use crate::packet::Packet;
use std::env;
use crate::network::{Packet, RoutingTable};

// TODO: Update the Host so that it has a parameter with a specific interface. This would mean that UdpSocket is unnecessary here
#[derive(Debug)]
pub struct Host {
    pub interface: InterfaceConfig,
    pub neighbors: Vec<NeighborConfig>,
    pub routing_mode: RoutingType,
    pub static_routes: Vec<StaticRoute>,
    // forwarding table

    pub forwarding_table: RoutingTable,

}

impl Host {
    // TODO: intiialize the interface as part of the Host
    pub fn new(ip_config: &IPConfig) -> Host {
        forwarding_table = RoutingTable::new(&ip_config); 
        Host { 
            interface: ip_config.interfaces[0], // Assume that lnx is properly formatted
            neighbors: ip_config.neighbors, routing_mode:
            ip_config.routing_mode, 
            static_routes: ip_config.static_routes,
            forwarding_table, 
        }

        // call initialize routing table fucntion 
        
    }

    // TODO: update this function so that Host calls the send function from the interface
    pub fn send_data(&self, destination_ip: IpAddr, data: &[u8]) -> Result<(), std::io::Error> {
        let packet = Packet::new(self.ip_addr, destination_ip, 17, data.to_vec());
        self.socket.send_to(&packet.to_bytes(), 0)?;
        Ok(())
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
    Host::new(&ip_config);
}