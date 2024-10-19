use etherparse::{Ipv4Header, Ipv4HeaderSlice, PacketBuilder, IpNumber};
// use etherparse::checksum::u32_16bit_word;
use std::net::Ipv4Addr;

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
    // Create a new Packet struct using etherparse::PacketBuilder
    pub fn new(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, protocol: u8, payload: Vec<u8>) -> Packet {
        // Create the PacketBuilder for IPv4
        let builder = PacketBuilder::ipv4(
            src_ip.octets(),    // Source IP address
            dest_ip.octets(),   // Destination IP address
            20                 // TTL (time to live)
        );

        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut result, Self::protocol_to_ipnumber(protocol), &payload).unwrap();

        Packet {
            src_ip,
            dest_ip,
            protocol,   // Custom protocol (0 for Test Protocol, 200 for RIP)
            payload: result,   // The raw byte representation of the payload
            ttl: 20,           // TTL field (set to 20 here, can be changed)
            header_checksum: 0, // You can set the checksum manually if needed
        }
    }

    // Convert custom protocol number to IpNumber
    fn protocol_to_ipnumber(protocol: u8) -> IpNumber {
        match protocol {
            0 => IpNumber::UDP, // Assuming you create this variant in your enum
            200 => IpNumber::IPV4, // Similarly for RIP
            _ => IpNumber::from(protocol), // Use the default conversion for other protocols
        }
    }

    fn ipnumber_to_protocol(ipnumber: IpNumber) -> u8 {
        match ipnumber {
            IpNumber::UDP => 0,
            IpNumber::IPV4 => 200,
            _ => 50, // just random for now
        }
    }

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
                    protocol: Self::ipnumber_to_protocol(protocol),
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
        // Create an IPv4 header using etherparse
        let header = match Ipv4Header::new(
            self.payload.len() as u16,
            self.ttl,
            Self::protocol_to_ipnumber(self.protocol),
            self.src_ip.octets(),
            self.dest_ip.octets(),
        ) {
            Ok(header) => header,
            Err(err) => {
                // Handle the error here, for example:
                panic!("Failed to create Ipv4Header: {}", err);
            }
        };

        let mut packet_bytes = Vec::new();
        // Serialize the header to bytes
        packet_bytes.extend_from_slice(&header.to_bytes());
        // Append the actual payload
        packet_bytes.extend_from_slice(&self.payload);

        packet_bytes
    }
        
    //     // Recompute checksum for the header
    //     ip_header.header_checksum = Packet::compute_checksum(&ip_header);

    //     // Serialize header and payload into raw bytes
    //     let mut packet_bytes = Vec::new();
    //     packet_bytes.extend_from_slice(&ip_header.to_bytes());
    //     packet_bytes.extend_from_slice(&self.payload);

    //     packet_bytes
    // }

    // Compute the checksum using the netstack package
    pub fn compute_checksum(header: &Ipv4Header) -> u16 {
        let header_bytes = header.to_bytes();
        let mut checksum: u32 = 0;

        // Sum all 16-bit words in the header
        for i in (0..header_bytes.len()).step_by(2) {
            let word = if i + 1 < header_bytes.len() {
                (header_bytes[i] as u32) << 8 | (header_bytes[i + 1] as u32) // Combine two bytes into one 16-bit word
            } else {
                (header_bytes[i] as u32) << 8 // If there's an odd byte, pad with zero
            };

            checksum = checksum.wrapping_add(word); // Add the word to the checksum
        }

        // Fold the 32-bit sum to 16 bits
        while checksum >> 16 != 0 {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }

        // Return the one's complement of the checksum
        !(checksum as u16)
    }

    // Extract the destination IP address from a raw packet
    pub fn extract_dest_ip(raw_packet: &[u8]) -> Result<Ipv4Addr, String> {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => Ok(ip_slice.destination_addr()),
            Err(err) => Err(format!("Failed to extract destination IP: {}", err)),
        }
    }

    pub fn extract_src_ip(raw_packet: &[u8]) -> Result<Ipv4Addr, String> {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => Ok(ip_slice.source_addr()),
            Err(err) => Err(format!("Failed to extract source IP: {}", err)),
        }
    }

    // Extract the protocol from a raw packet
    pub fn extract_protocol(raw_packet: &[u8]) -> Result<u8, String> {
        match Ipv4HeaderSlice::from_slice(raw_packet) {
            Ok(ip_slice) => Ok(Self::ipnumber_to_protocol(ip_slice.protocol())),
            Err(err) => Err(format!("Failed to extract protocol: {}", err)),
        }
    }

    // Check if packet is local
    pub fn is_local(&self, curr_ip: Ipv4Addr) -> bool {
        curr_ip.octets() == self.dest_ip.octets()
    }
}