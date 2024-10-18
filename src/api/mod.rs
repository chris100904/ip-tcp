use std::sync::mpsc::Sender;

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

#[derive(Debug)]
pub struct InterfaceStruct {
    pub config: InterfaceConfig,
    pub enabled: bool,
    pub interface: NetworkInterface,
}

impl InterfaceStruct {
    pub fn new(config: InterfaceConfig, packet_sender: Sender<Vec<u8>> ) -> InterfaceStruct {
        return InterfaceStruct {
            interface: NetworkInterface::new(&config, packet_sender),
            config: config,
            enabled: true,
        }
    }
}