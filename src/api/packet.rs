use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, PacketBuilder, TcpHeader, TcpHeaderSlice, TcpOptions};
// use etherparse::checksum::u32_16bit_word;
use std::{io::Error, net::Ipv4Addr};

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

#[derive(Debug)]
pub struct RipPacket {
  pub command: u16,
  pub num_entries: u16,
  pub entries: Vec<Entry>
}

#[derive(Debug)]
pub struct TcpPacket {
  pub src_port: u16,
  pub dest_port: u16,
  pub seq_num: u32,
  pub ack_num: u32, 
  pub data_offset: u8,
  pub flags: TcpFlags,
  pub window: u16,
  pub checksum: u16,
  pub urgent_pointer: u16,
  pub options: Vec<u8>,
  pub payload: Vec<u8>
}

#[derive(Debug)]
pub struct TcpFlags {
  pub syn: bool,
  pub ack: bool,
  pub fin: bool,
  pub rst: bool,
  // pub psh: bool,
  // pub urg: bool,
  // pub ece: bool,
  // pub cwr: bool,
}
#[derive(Debug)]
pub struct Entry {
  pub cost: u32,
  pub address: u32,
  pub mask: u32
}

impl RipPacket {
  pub fn new(command: u16, num_entries: u16, entries: Vec<Entry>) -> RipPacket {
    RipPacket {
      command,
      num_entries,
      entries
    }
  }

  pub fn serialize_rip(&self) -> Vec<u8> {
    let mut rip_bytes = Vec::with_capacity(4 + self.entries.len() * 12);

    rip_bytes.extend_from_slice(&self.command.to_be_bytes());
    rip_bytes.extend_from_slice(&self.num_entries.to_be_bytes());

    for entry in &self.entries {
        rip_bytes.extend_from_slice(&entry.cost.to_be_bytes());
        rip_bytes.extend_from_slice(&entry.address.to_be_bytes());
        rip_bytes.extend_from_slice(&entry.mask.to_be_bytes());
    }

    rip_bytes
  }

  fn extract_u16(slice: &[u8], range: std::ops::Range<usize>) -> Result<u16, String> {
      slice.get(range)
          .ok_or("Failed to extract bytes for u16")?
          .try_into()
          .map(u16::from_be_bytes)
          .map_err(|_| "u16 conversion failed".to_string())
  }

  fn extract_u32(slice: &[u8], range: std::ops::Range<usize>) -> Result<u32, String> {
      slice.get(range)
          .ok_or("Failed to extract bytes for u32")?
          .try_into()
          .map(u32::from_be_bytes)
          .map_err(|_| "u32 conversion failed".to_string())
  }
}

impl TcpPacket {
  pub fn serialize_tcp(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut tcp_header = TcpHeader::new(
      self.src_port,     // source port
      self.dest_port,     // destination port
      self.seq_num,  // sequence number
      self.window,   // window size
    );
    tcp_header.ack = self.flags.ack;
    tcp_header.syn = self.flags.syn;
    tcp_header.rst = self.flags.rst;
    tcp_header.fin = self.flags.fin;
    tcp_header.acknowledgment_number = self.ack_num;
    tcp_header.urgent_pointer = self.urgent_pointer;
    tcp_header.options = TcpOptions::try_from_slice(&self.options).unwrap();
    
    tcp_header.checksum = tcp_header
      .calc_checksum_ipv4_raw(src_ip.octets(), dst_ip.octets(), &self.payload)
      .expect("Failed to calculate TCP checksum");

    // Buffer to hold the TCP header and payload
    let mut result: Vec<u8> = Vec::with_capacity(tcp_header.header_len() as usize + self.payload.len());

    // Write the TCP header into the buffer
    tcp_header.write(&mut result);

    // Append the TCP payload
    result.extend_from_slice(&self.payload);

    result
  }

  pub fn parse_tcp(raw_data: &[u8]) -> Result<TcpPacket, String> {
    let tcp_slice = TcpHeaderSlice::from_slice(raw_data)
        .map_err(|e| format!("Failed to parse TCP header: {}", e))?;

    let header = tcp_slice.to_header();

    // Calculate the header length
    let header_len = tcp_slice.slice().len() as usize;

    // Extract payload
    let payload = &raw_data[header_len..];

    // TODO: Validations? (Flags, checksum)
    Ok(TcpPacket {
        src_port: header.source_port,
        dest_port: header.destination_port,
        seq_num: header.sequence_number,
        ack_num: header.acknowledgment_number,
        data_offset: tcp_slice.data_offset() as u8,
        flags: TcpFlags { syn: header.syn, ack: header.ack, fin: header.fin, rst: header.rst }, 
        window: header.window_size,
        checksum: header.checksum,
        urgent_pointer: header.urgent_pointer,
        options: tcp_slice.options().to_vec(),
        payload: payload.to_vec(),
    })
  }
}

impl Packet {
    // Create a new Packet struct using etherparse::PacketBuilder
    pub fn new(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, protocol: u8, payload: Vec<u8>) -> Packet {
        Packet {
            src_ip,
            dest_ip,
            protocol,   // Custom protocol (0 for Test Protocol, 200 for RIP)
            payload,   // The raw byte representation of the payload
            ttl: 16,           // TTL field (set to 20 here, can be changed)
            header_checksum: 0, // You can set the checksum manually if needed
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
                    protocol: protocol.0,
                    payload,
                    ttl,
                    header_checksum,
                })
            },
            Err(err) => Err(format!("Failed to parse IP packet: {:?}", err)), 
        }
    }

    // Serialize the packet
    pub fn serialize(&self) -> Vec<u8> {
        // Create an IPv4 header using etherparse
        // Create the PacketBuilder for IPv4
        let builder = PacketBuilder::ipv4(
          self.src_ip.octets(),    // Source IP address
          self.dest_ip.octets(),   // Destination IP address
          16                 // TTL (time to live)
        );
        
        let protocol: IpNumber = self.protocol.into();
        let mut result = Vec::<u8>::with_capacity(builder.size(self.payload.len()));
        builder.write(&mut result, protocol, &self.payload).unwrap();

        result
    }
  
  pub fn parse_rip_message(&self) -> Result<RipPacket, String> {
      let command = RipPacket::extract_u16(&self.payload, 0..2)?;
      let num_entries = RipPacket::extract_u16(&self.payload, 2..4)?;
      
      let mut entries = Vec::with_capacity(num_entries as usize);
  
      for i in 0..num_entries {
          let base = 4 + 12 * i as usize;
          entries.push(Entry {
              cost: RipPacket::extract_u32(&self.payload, base..base + 4)?,
              address: RipPacket::extract_u32(&self.payload, base + 4..base + 8)?,
              mask: RipPacket::extract_u32(&self.payload, base + 8..base + 12)?,
          });
      }
  
      Ok(RipPacket {
          command,
          num_entries,
          entries,
      })
  }
}