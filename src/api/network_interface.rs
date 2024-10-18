use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use super::parser::{InterfaceConfig, RoutingType};




pub struct NetworkInterface {
    udp_socket: Arc<Mutex<UdpSocket>>,
}

pub trait Device {
    fn send_data(&self, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), std::io::Error>;
    fn receive_packet(&mut self) -> Result<Vec<u8>, std::io::Error>;
}

impl NetworkInterface {
    pub fn new(ip_config: InterfaceConfig, packet_sender: Sender<Vec<u8>>) -> NetworkInterface {
        let udp_addr = ip_config.udp_addr;
        let udp_port = ip_config.udp_port;
        let udp_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(udp_addr), udp_port)).unwrap();

        let udp_socket = Arc::new(Mutex::new(udp_socket)); // Wrap the UdpSocket in an Arc and a Mutex

        let socket_clone = udp_socket.clone();
        thread::spawn(move || {
            Self::listen_for_packets(socket_clone, packet_sender); // Pass the channel sender to listen_for_packets
        });

        NetworkInterface { udp_socket }
    }

    fn listen_for_packets(udp_socket: Arc<Mutex<UdpSocket>>, sender: Sender<Vec<u8>>) {
        loop {
            let mut buf = [0; 1500];
            match udp_socket.lock().unwrap().recv_from(&mut buf) {
                Ok((size, _)) => {
                    let packet = buf[..size].to_vec();  // Create packet data from received buffer
                    if let Err(e) = sender.send(packet) {
                        eprintln!("Error sending packet to parent: {}", e);
                        break;
                    }
                    println!("Received packet of size {}", size);
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }
    }

    // pub fn send_data(&self, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), std::io::Error> {
    //     self.udp_socket.lock().send_to(data, 0, &format!("{}:0", destination_ip))?;
    //     Ok(())
    // }

    // // TODO: implement this function to send up to the parent device
    // pub fn send_to_parent(sender: Sender<()>) -> Result<(), std::io::Error> {   
    //     sender.send()
    //     Ok(())
    // }
}


