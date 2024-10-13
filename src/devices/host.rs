pub struct Host {
    // Fields specific to the Host
}

impl NetworkDevice for Host {
    fn send_data(&self, destination_ip: IpAddr, data: &[u8]) -> Result<(), Error> {
        // Implement sending data from the host
    }

    fn receive_packet(&self) -> Result<Packet, Error> {
        // Implement receiving packet logic for the host
    }

    fn process_received_packet(&self, packet: Packet) {
        // Process the received packet
    }
}
