pub mod network_interface;
pub mod packet;
pub mod parser;
pub mod repl;
pub mod routing_table;
pub mod device;
pub mod tcp_listener;
pub mod tcp_stream;

pub enum Command {
    ListInterfaces,
    ListNeighbors,
    ListRoutes,
    DisableInterface(String),
    EnableInterface(String),
    SendTestPacket(String, String),
    Exit,
    ListenAccept(String),
    TCPConnect(String, String),
    TCPSend(u32, String),
    TCPReceive(u32, u32),
    TCPClose(u32),
    ListSockets,
    SendFile(String, String, u32),
    ReceiveFile(String, u32),
}