use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::sync::{Arc, Mutex};
use crate::api::packet::Packet;
use std::sync::mpsc::Sender;
use super::parser::InterfaceConfig;



#[derive(Debug)]
pub struct NetworkInterface {
    udp_socket: Arc<Mutex<UdpSocket>>,
}

pub trait Device {
    fn send_data(&self, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), std::io::Error>;
    fn receive_packet(&mut self) -> Result<Vec<u8>, std::io::Error>;
}

impl NetworkInterface {
    pub fn new(ip_config: &InterfaceConfig, packet_sender: Sender<Packet>) -> NetworkInterface {
        let udp_addr = ip_config.udp_addr;
        let udp_port = ip_config.udp_port;
        let udp_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(udp_addr), udp_port)).unwrap();
        udp_socket.set_nonblocking(true).expect("whatever");

        let udp_socket = Arc::new(Mutex::new(udp_socket)); // Wrap the UdpSocket in an Arc and a Mutex

        let socket_clone = udp_socket.clone();
        thread::spawn(move || {
            Self::listen_for_packets(socket_clone, packet_sender); // Pass the channel sender to listen_for_packets
        });

        NetworkInterface { udp_socket }
    }

    fn listen_for_packets(udp_socket: Arc<Mutex<UdpSocket>>, sender: Sender<Packet>) {
        loop {
            let mut buf = [0; 1500];
            match udp_socket.lock().unwrap().recv_from(&mut buf) {
                Ok((size, _)) => {
                    let packet = buf[..size].to_vec();  // Create packet data from received buffer
                    match Packet::parse_ip_packet(&packet) {
                        Ok(parsed_packet) => {
                            if let Err(e) = sender.send(parsed_packet) {
                                eprintln!("Error sending packet to parent: {}", e);
                                break;
                            }
                            println!("Received packet of size {}", size);
                        }
                        Err(e) => {
                            eprintln!("Error parsing packet: {}", e);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking mode, so we just continue looping without holding the lock for too long
                    thread::sleep(std::time::Duration::from_millis(10)); // Sleep for a short duration to avoid busy looping
                    continue;
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }
    }

    pub fn send_packet(&self, packet: Packet, udp_addr: Ipv4Addr, dest_port: u16) {
        // Serialize the packet into a byte buffer (you may need to define this method)
        let serialized_packet = packet.to_bytes();
        // Extract destination IP and port (this might be part of your packet structure)

        let destination_addr = SocketAddr::new(IpAddr::V4(udp_addr), dest_port);

        // Lock the UDP socket and send the packet
        match self.udp_socket.lock().unwrap().send_to(&serialized_packet, destination_addr) {
            Ok(sent_bytes) => {
                println!("Successfully sent {} bytes to {}.", sent_bytes, destination_addr);
            }
            Err(e) => {
                eprintln!("{:?}", destination_addr);
                eprintln!("Error sending packet: {}", e);
            }
        }
    }
}


