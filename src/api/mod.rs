pub mod network_interface;
pub mod packet;
pub mod parser;
pub mod repl;
pub mod routing_table;
pub mod device;
// pub mod socket;

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
  ListenAccept(String),
  TCPConnect(String, String),
  TCPSend(u32, String),
  TCPReceive(u32, u32),
  TCPClose(u32),
  ListSockets,
  SendFile(String, String, u32),
  ReceiveFile(String, u32),
}