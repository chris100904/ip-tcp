use etherparse::{Ipv4HeaderSlice, Ipv4Header};

#[derive(Debug)]
pub struct Packet {
    // Fields representing the packet structure (e.g., headers, payload)
    pub src_ip: std::net::Ipv4Addr,
    pub dest_ip: std::net::Ipv4Addr,
    pub protocol: u8,
    pub payload: Vec<u8>, // actual data carried
    pub ttl: u8, // time to live 
    pub header_checksum: u16, // error-checking header 
}

impl Packet {
    // Parse the IP header and return a Packet struct
    pub fn parse_ip_packet(raw_data: &[u8]) -> Result<Packet, String> {
        match Ipv4HeaderSlice::from_slice(raw_data) {
            Ok(ip_slice) => {
                let src_ip = ip_slice.source_addr();
                let dest_ip = ip_slice.destination_addr();
                let protocol = ip_slice.protocol();
                let ttl = ip_slice.ttl();
                let header_checksum = ip_slice.header_checksum();

                // extract payload
                let payload_len = ip_slice.payload_len().unwrap_or(0); // default to 0 if the length is not available
                // start from the end of the IP header and end at the end of the payload
                let payload = raw_data[ip_slice.slice().len()..ip_slice.slice().len() + payload_len as usize].to_vec();

                Ok(Packet {
                    src_ip,
                    dest_ip,
                    protocol,
                    payload,
                    ttl,
                    header_checksum,
                })
            },
            Err(err) => Err(format!("Failed to parse IP packet: {:?}", err)), 
        }
    }

    // Serialize the packet
    pub fn to_bytes(&self) -> Vec<u8> {
        // Build the IP header and append payload
        let mut ip_header = Ipv4Header::new(
            (self.payload.len() + 20) as u16, 
            self.ttl,
            self.protocol,                    
            self.src_ip.octets(),             
            self.dest_ip.octets()             
        );
        
        // Recompute checksum for the header
        ip_header.header_checksum = Packet::compute_checksum(&ip_header);

        // Serialize header and payload into raw bytes
        let mut packet_bytes = Vec::new();
        packet_bytes.extend_from_slice(&ip_header.to_bytes());
        packet_bytes.extend_from_slice(&self.payload);

        packet_bytes
    }
    // Calculate checksum for the packet
    pub fn compute_checksum(header: &Ipv4Header) -> u16 {
        let mut checksum = 0;
        let header_bytes = header.to_bytes();

        for i in (0..header_bytes.len()).step_by(2) {
            // create a u16 word by shifting the first byte 8 bits left and adding the second byte
            let word = ((header_bytes[i] as u16) << 8) | (header_bytes[i + 1] as u16);

            // use wrapping_add in case there is overflow (shouldn't exceed max value?)
            checksum = checksum.wrapping_add(word);
        }

        // handle case where checksum exceeds 16 bits by adding the overflow bits
        while checksum >> 16 != 0 {
            checksum = (checksum >> 16) + (checksum & 0xffff);
        }

        !checksum as u16
    }

    // Extract the destination IP address from a raw packet
    pub fn extract_dest_ip(raw_packet: &[u8]) -> IpAddr {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => ip_slice.destination_addr(),
            Err(err) => Err(format!("Failed to extract destination IP: {}", err)),
        }
    }

    // Extract the source IP address from a raw packet
    pub fn extract_src_ip(raw_packet: &[u8]) -> IpAddr {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => ip_slice.source_addr(),
            Err(err) => Err(format!("Failed to extract source IP: {}", err)),
        }
    }

    // Extract the protocol from a raw packet
    pub fn extract_protocol(raw_packet: &[u8]) -> u8 {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => ip_slice.protocol(),
            Err(err) => Err(format!("Failed to extract protocol: {}", err)),
        }
    }

    // Check if packet is local
    pub fn is_local(&self) -> bool {
        self.src_ip.octets() == self.dest_ip.octets()
    }
}