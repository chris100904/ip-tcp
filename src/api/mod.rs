pub mod network_interface;
pub mod packet;
pub mod parser;
pub mod repl;
pub mod routing_table;
pub mod device;

pub enum Command {
    ListInterfaces,
    ListNeighbors,
    ListRoutes,
    DisableInterface(String),
    EnableInterface(String),
    SendTestPacket(String, String),
    Exit,
}