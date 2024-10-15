use std::net::{UdpSocket, SocketAddr, Ipv4Addr};

// UDP socket handling functions

pub fn create_socket(local_ip: Ipv4Addr) -> Result<Socket, Error> {
    let socket = UdpSocket::bind(format!("{}:0", local_ip))?;
    Ok(socket)
}

pub fn send_data(socket: &UdpSocket, destination_ip: Ipv4Addr, data: &[u8]) -> Result<(), Error> {
    // socketaddr::new??? 
    socket.send_to(data, SocketAddr::new(destination_ip, 0))?;
    Ok(())
}

pub fn receive_packet(socket: &Socket) -> Result<Vec<u8>, Error> {
    // Receive a packet from the UDP socket
    let mut buf = [0; 1500];
    let (size, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..size].to_vec())
}
