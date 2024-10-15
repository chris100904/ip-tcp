pub struct NetworkLayer {
    pub interfaces: Vec<Box<dyn NetworkInterface>>, 
    pub routing_table: Option<RoutingTrie>,
}

impl NetworkLayer {
    pub fn new(interfaces: Vec<Box<dyn NetworkInterface>>, routing_table: Option<RoutingTrie>) -> Self {
        NetworkLayer {
            interfaces,
            routing_table,
        }
    }

    // Handles an incoming IP packet
    pub fn receive_packet(&self, packet: Packet) {
        // Validate the packet (e.g., checksum, TTL)
        if self.is_valid_packet(&packet) {
            if let Some(routing_table) = &self.routing_table {
                // Forward to the determined interface
                match routing_table.lookup(packet.dest_ip) {
                    Some(interface) => {
                        interface.send_data(packet.dest_ip, &packet);
                    },
                    None => {
                        println!("No route found for IP: {}", packet.dest_ip);
                    }
                }
            } else {
                // Host, check if the packet is meant for this host (based on IP)
                if self.interfaces.iter().any(|interface| interface.get_ip() == packet.dest_ip) {
                    println!("Received packet for this host: {:?}", packet);
                    // Further processing for application layer can go here
                } else {
                    println!("Packet not for this host, dropping...");
                }
            }
        }
    }

    // Checks if the packet is valid (e.g., TTL > 0, checksum)
    fn is_valid_packet(&self, packet: &Packet) -> bool {
        // Basic validation (can be expanded)
        packet.ttl > 0 && Packet::compute_checksum(packet) == packet.header_checksum
    }

    fn is_router(&self) -> bool {
        self.routing_table.is_some()
    }
}