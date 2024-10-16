use std::net::{UdpSocket, SocketAddr};
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

pub struct NetworkInterface {
    parent_device: Box<dyn Device>,
    udp_socket: Arc<Mutex<UdpSocket>>,
    listening_thread: thread::JoinHandle<()>,
}

pub trait Device {
    fn send_data(&self, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), std::io::Error>;
    fn receive_packet(&mut self) -> Result<Vec<u8>, std::io::Error>;
}

impl NetworkInterface {
    pub fn new(parent_device: Box<dyn Device>, udp_socket: UdpSocket) -> NetworkInterface {
        let udp_socket = Arc::new(Mutex::new(udp_socket));
        let listening_thread = thread::spawn(move || {
            listen_for_packets(udp_socket);
        });
        NetworkInterface {
            parent_device,
            udp_socket,
            listening_thread,
        }
    }

    fn listen_for_packets(udp_socket: Arc<Mutex<UdpSocket>>) {
        loop {
            let mut buf = [0; 1500];
            match udp_socket.lock().recv_from(&mut buf) {
                Ok((size, _)) => {
                    // Process the packet
                    // maybe send up to the parent device
                    send_to_parent(&buf[..size]);
                    println!("Received packet of size {}", size);
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }
    }

    pub fn send_data(&self, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), std::io::Error> {
        self.udp_socket.lock().send_to(data, 0, &format!("{}:0", destination_ip))?;
        Ok(())
    }

    // TODO: implement this function to send up to the parent device
    fn send_to_parent(&self, data: &[u8]) -> Result<(), std::io::Error> {
    }
}