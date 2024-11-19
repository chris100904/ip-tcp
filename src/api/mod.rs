use std::net::Ipv4Addr;

pub mod network_interface;
pub mod packet;
pub mod parser;
pub mod repl;
pub mod routing_table;
pub mod device;
pub mod socket;
pub mod tcp;
pub mod error;
pub mod buffer;

pub enum CommandType {
  IP(IPCommand),
  TCP(TCPCommand)
}
pub enum IPCommand {
    ListInterfaces,
    ListNeighbors,
    ListRoutes,
    DisableInterface(String),
    EnableInterface(String),
    SendTestPacket(String, String),
    Exit,
}

pub enum TCPCommand {
  ListenAccept(u16),
  TCPConnect(Ipv4Addr, u16),
  TCPSend(u32, String),
  TCPReceive(u32, u32),
  TCPClose(u32),
  ListSockets,
  SendFile(String, Ipv4Addr, u16),
  ReceiveFile(String, u16),
}