use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use etherparse::{Ipv4HeaderSlice, Ipv4Header};
use crate::packet::Packet;

#[derive(Debug)]
pub struct Host {
    pub ip_addr: Ipv4Addr,
    pub mac_addr: [u8; 6],
    socket: UdpSocket,
}

impl Host {
    pub fn new(ip_addr: Ipv4Addr, mac_addr: [u8; 6]) -> Host {
        let socket = UdpSocket::bind(format!("{}:0", ip_addr)).unwrap(); // bind to IP
        Host { ip_addr, mac_addr, socket }
    }

    pub fn send_data(&self, destination_ip: IpAddr, data: &[u8]) -> Result<(), std::io::Error> {
        let packet = Packet::new(self.ip_addr, destination_ip, 17, data.to_vec());
        self.socket.send_to(&packet.to_bytes(), 0)?;
        Ok(())
    }

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

    pub fn process_packet(&mut self, raw_data: &[u8]) {
        if let Ok(packet) = Packet::parse_ip_packet(raw_data) {
            println!("Received packet from {}: {:?}", packet.src_ip, packet);
            // Handle the packet
        }
    }
}
