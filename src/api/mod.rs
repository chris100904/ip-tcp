use network_interface::NetworkInterface;
use parser::InterfaceConfig;

pub mod network_interface;
pub mod packet;
pub mod parser;
pub mod repl;
pub mod routing_table;


pub enum Command {
    ListInterfaces,
    ListNeighbors,
    ListRoutes,
    DisableInterface(String),
    EnableInterface(String),
    SendTestPacket(String, String),
    Exit,
}

pub struct InterfaceState {
    pub config: InterfaceConfig,
    pub enabled: bool,
    pub interface: NetworkInterface,
}