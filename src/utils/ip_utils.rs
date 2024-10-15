use std::net::Ipv4Addr;
use crate::network::packet::Packet;

pub fn is_local(packet: &Packet) -> bool {
    packet.src_ip.octets() == packet.dest_ip.octets()
}

/* 
Not sure exactly which functions would be put here as 
part of the API, but these are just a bunch of helper functions for IP
functionality. Most of this can be easily handled in the functions that call them, 
so it's not really necessary. 
*/