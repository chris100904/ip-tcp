use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use etherparse::IpNumber;

use super::network_interface::NetworkInterface;
use super::packet::{self, Entry, Packet, RipPacket};
use super::routing_table::{NextHop, Route, Table};
use super::parser::{IPConfig, InterfaceConfig, NeighborConfig, RoutingType, StaticRoute};
use super::IPCommand;

#[derive(Debug)]
pub struct InterfaceStruct {
    pub config: InterfaceConfig,
    pub enabled: bool,
    pub interface: NetworkInterface,
}

impl InterfaceStruct {
    pub fn new(config: InterfaceConfig, packet_sender: Sender<(Packet, Ipv4Addr)> ) -> InterfaceStruct {
        return InterfaceStruct {
            interface: NetworkInterface::new(&config, packet_sender),
            config: config,
            enabled: true,
        }
    }
}
pub struct Device {
  pub interfaces: Vec<InterfaceStruct>, // Should only contain one for host devices
  pub neighbors: Vec<NeighborConfig>,
  pub routing_mode: RoutingType,
  pub static_routes: Vec<StaticRoute>, // empty for routers
  // routing table 
  pub routing_table: Table,
  
  // ROUTERS ONLY: Timing parameters for RIP updates (in milliseconds)
  pub rip_neighbors: Option<Vec<Ipv4Addr>>,
  pub rip_periodic_update_rate: Option<u64>,
  pub rip_timeout_threshold: Option<u64>,

  // HOSTS ONLY: Timing parmeters for TCP (in milliseconds)
  pub tcp_rto_min: Option<u64>,
  pub tcp_rto_max: Option<u64>,
}

impl Device {
  // TODO: intiialize the interface as part of the Host
  pub fn new(ip_config: &IPConfig, packet_sender: Sender<(Packet, Ipv4Addr)>) -> Device {
      let routing_table = Table::new(ip_config);
      let mut ifstructs: Vec<InterfaceStruct> = Vec::new();
      for interface in ip_config.interfaces.clone() {
          ifstructs.push(InterfaceStruct::new(interface, packet_sender.clone()));
      }
      
      Device { 
        interfaces: ifstructs, // Assume that lnx is properly formatted
        neighbors: ip_config.neighbors.clone(), 
        routing_mode: ip_config.routing_mode.clone(), 
        static_routes: ip_config.static_routes.clone(),
        routing_table,
        // ROUTERS ONLY: Timing parameters for RIP updates (in milliseconds)
        rip_neighbors: ip_config.rip_neighbors.clone(),
        rip_periodic_update_rate: ip_config.rip_periodic_update_rate.clone(),
        rip_timeout_threshold: ip_config.rip_timeout_threshold.clone(),

        // HOSTS ONLY: Timing parmeters for TCP (in milliseconds)
        tcp_rto_min: ip_config.tcp_rto_min.clone(),
        tcp_rto_max: ip_config.tcp_rto_max.clone(),
      }
  }

  pub fn ip_protocol_handler(device: Arc<Mutex<Device>>, receiver: Receiver<IPCommand>) {
      loop {
          match receiver.recv() {
              Ok(command) => {
                  loop {
                      if let Ok(mut safe_device) = device.try_lock() {
                          match command {
                              IPCommand::ListInterfaces => safe_device.list_interfaces(),
                              IPCommand::ListNeighbors => safe_device.list_neighbors(),
                              IPCommand::ListRoutes => safe_device.list_routes(),
                              IPCommand::DisableInterface(ifname) => safe_device.disable_interface(&ifname),
                              IPCommand::EnableInterface(ifname) => safe_device.enable_interface(&ifname),
                              IPCommand::SendTestPacket(addr, msg) => safe_device.send_test_packet(&addr, &msg),
                              IPCommand::Exit => break,
                          }
                          break;
                      }
                  }
              }
              Err(_) => break,
          }
      }
  }

  pub fn receive_from_interface(device: Arc<Mutex<Device>>, 
    receiver: Receiver<(Packet, Ipv4Addr)>, ip_send_tcp: Option<Sender<(Packet, Ipv4Addr)>>) {
    loop {
      match receiver.recv() {
        Ok((packet, src_ip)) => { 
          loop {
            // check if the packet protocol is TCP --> send back to vhost
            if let Ok(mut safe_device) = device.try_lock() {
              for interface in &safe_device.interfaces {
                if interface.config.udp_addr == src_ip {
                  if interface.enabled {
                    // println!("RECEIVING FROM INTERFACE\n");
                    // check if the packet dest_ip matches any of the interfaces
                    if safe_device.is_packet_for_device(&packet.dest_ip) {
                      if packet.protocol == 200 {
                        safe_device.process_rip_packet(packet);
                      } else if packet.protocol == 0 {
                        safe_device.process_local_packet(packet);
                      } else if packet.protocol == IpNumber::TCP.0 {
                        if let Some(ref sender) = ip_send_tcp {
                          sender.send((packet, src_ip));
                        }
                      }
                    } else {
                        // packet is not meant for this device, so we need to forward it
                        match safe_device.routing_table.lookup(packet.dest_ip) {
                            Some(route) => {
                                // println!("ROUTE: {:?}", route);
                                safe_device.forward_packet(packet, route.next_hop.clone());
                            }
                            None => {
                                eprintln!("Error: No valid interface found for destination IP: {}", packet.dest_ip);
                            }
                        }
                    }
                    break;
                  }
                }
              }
            } else {
                // If the interface is disabled, you can log or handle it accordingly
                eprintln!("Interface {} is disabled, packet dropped.", src_ip);
            }
            break;
          }
        } 
        Err(e) => eprintln!("ERROR!: {e}"),
      }
    }
  }


  pub fn list_interfaces(&self) {
      println!("Name  Addr/Prefix State");
      
      for interface in &self.interfaces {
          println!("{}  {:<15} {}", 
              interface.config.name, 
              format!("{}/{}", 
                  interface.config.assigned_ip, 
                  interface.config.assigned_prefix.prefix_len()), 
              if interface.enabled {"up"} else {"down"});
      }
  }

  pub fn list_neighbors(&self) {
      println!("Iface VIP  UDPAddr");
      for interface in &self.interfaces {
          if interface.enabled {
              for neighbor in &self.neighbors {
                  if neighbor.interface_name == interface.config.name {
                      println!("{}     {}     {}", interface.config.name, neighbor.dest_addr, 
                        neighbor.udp_addr.to_string() + ":" + &neighbor.udp_port.to_string());
                  }
              }
          }
      }
  }

  pub fn list_routes(&mut self) {
      println!("T       Prefix   Next hop   Cost");
      let timeout = if let Some(rip_timeout) = self.rip_timeout_threshold {
          Some(rip_timeout)
      } else {
          None
      };
      for route in &self.routing_table.get_routes(timeout) {
          let routing_type = match route.routing_mode {
              RoutingType::None => "L".to_string(),
              RoutingType::Static => "S".to_string(),
              RoutingType::Rip => "R".to_string()
          };
          let prefix = route.prefix.to_string();
          let next_hop: String = match &route.next_hop {
              NextHop::Interface(interface) => {
                  format!("LOCAL:{}", interface.name).to_string()
              },
              NextHop::IPAddress(ip_addr) => {
                  ip_addr.to_string()
              }
              NextHop::RIPAddress(prefix) => {
                  prefix.addr().to_string()
              }
          };
          let cost = match route.cost{
              Some(cost) => cost.to_string(),
              None => "-".to_string()
          };
          println!("{}       {}   {}   {}", routing_type, prefix, next_hop, cost);
      }
  }

  pub fn disable_interface(&mut self, ifname: &str) {
      for ifstruct in &mut self.interfaces {
          if ifstruct.config.name == ifname {
              ifstruct.enabled = false;
              break;
          }
      }
  }

  pub fn enable_interface(&mut self, ifname: &str) {
      for ifstruct in &mut self.interfaces {
          if ifstruct.config.name == ifname {
              ifstruct.enabled = true;
              break;
          }
      }
  }

  pub fn send_test_packet(& mut self, addr: &str, message: &str) {
      let dest_ip = Ipv4Addr::from_str(addr).unwrap();
      let data = message.as_bytes();
      // the source ip is assumed to be one of the interfaces assigned ips? 
      let packet = Packet::new(self.interfaces[0].config.assigned_ip, dest_ip, 0, data.to_vec());

      if self.is_packet_for_device(&dest_ip) {
          self.process_local_packet(packet);
      } else {
          match self.routing_table.lookup(dest_ip) {
              Some(route) => {
                  self.forward_packet(packet, route.next_hop.clone()); // Forward the packet using forward_packet logic
              }
              None => {
                  eprintln!("Error: No valid route found for destination IP: {}", dest_ip);
              }
          }
      }
  }

  // Forward a packet to the next hop (another router or destination)
  pub fn forward_packet(&self, packet: Packet, mut next_hop: NextHop) {
    loop {
      match next_hop {
        NextHop::Interface(interface) => {
          // println!("INTERFACE: {:?}", interface);
          if let Some(matching_interface_struct) = self.find_interface_by_name(&interface.name) {
            // iterate through neighbors to find matching neighbor's interface's port
            if let Some((neighbor_addr, neighbor_port)) = self.find_neighbor_socket(&matching_interface_struct) {
              // Send the packet along with the neighbor's port number
              matching_interface_struct.interface.send_packet(packet, neighbor_addr, neighbor_port);
              return; // Exit after sending the packet
            } else {
              eprintln!("Error: Neighbor interface not found for: {}", interface.name);
              return; // Exit if no matching neighbor interface is found
            }
          } else {
            eprintln!("Error: Interface not found: {}", interface.name);
            return;
          }
        }
          NextHop::IPAddress(ip_addr) => {
          /*
              Logic behind this is that it should eventually terminate by finding
              a proper interface to send through. If it never does, then we error print.
            */
          match self.routing_table.lookup(ip_addr) {
            Some(new_route) => {
                next_hop = new_route.next_hop.clone();
            }
            None => {
                eprintln!("Error: No valid interface found for destination IP: {}", ip_addr);
                return;
            }
          }  
        }
        NextHop::RIPAddress(prefix) => {
          match self.routing_table.lookup(prefix.addr()) {
            Some(new_route) => {
                next_hop = new_route.next_hop.clone();
            }
            None => {
                eprintln!("Error: No valid interface found for destination IP: {}", prefix.addr());
                return;
            }
          }  
          println!("Received rip address in forwarding table: {:?}", prefix);
        }
      }
    }
  }

  pub fn start_periodic_updates(device: Arc<Mutex<Device>>) {
    // send initial rip requests
    let rip_packet = RipPacket::new(1, 0, Vec::new());
    // println!("STARTING PERIODIC UPDATES. SENDING FIRST REQUEST BEFORE. COMMAND: {}\n", rip_packet.command);
    let mut interval = Duration::from_secs(5); // default to a 5 second interval
    loop {
      if let Ok(mut device) = device.try_lock() {
        device.send_rip_to_neighbors(rip_packet);
        // treat it like a rip request without any source of the request
        if let Some(rate) = device.rip_periodic_update_rate {
          interval = Duration::from_millis(rate); // get rate from device if specified
        }
        break;
      }
    }
    
    let mut last_update = Instant::now();

    loop {
      if last_update.elapsed() >= interval {
        // Lock the device to access routing table
        loop {
          if let Ok(mut device) = device.try_lock() {
            // treat it like a rip request without any source of the request
            device.send_rip_updates();
            break;
          }
        }
        last_update = Instant::now(); // Reset the timer
      }

      // Sleep for a short while to avoid busy looping
      thread::sleep(interval);
    }
  }

  pub fn send_rip_updates(&mut self) {
      let mut entries = Vec::new();
      for route in self.routing_table.get_routes(Some(self.rip_timeout_threshold.unwrap())) {
        if route.cost.unwrap() >= 16 {
            let cost: u32 = route.cost.unwrap().into();
            let address = route.prefix.addr().to_bits();
            let mask = route.prefix.netmask().to_bits();
            let entry = Entry {
                cost: cost.clone(), 
                address: address.clone(), 
                mask: mask.clone(),
            };
            // let rip_packet = RipPacket::new(2, 1, vec![entry]);
            entries.push(entry);
            // // println!("Sending RIP packet to neighbors: {:?}", rip_packet);
            // self.send_rip_to_neighbors(rip_packet);
            self.routing_table.remove_route(address, mask);
        } else if let NextHop::Interface(interface) = route.next_hop {
            if let Some(cost) = route.cost {
            entries.push(Entry { 
                cost: cost.into(), 
                address: interface.assigned_ip.to_bits(), 
                mask: interface.assigned_prefix.netmask().to_bits() })
            }
        } else if let NextHop::RIPAddress(ip) = route.next_hop{
          if let Some(cost) = route.cost {
            entries.push(Entry {
              cost: cost.into(),
              address: ip.addr().to_bits(),
              mask: ip.netmask().to_bits()
            })
          }
        }
    }
    // println!("Entries: {:?}", entries.len());
    let rip_packet = RipPacket::new(2, entries.len() as u16, entries);
    
    self.send_rip_to_neighbors(rip_packet);
}

  pub fn process_rip_packet(&mut self, packet: Packet) {
    let rip_message = packet.parse_rip_message();
    match rip_message {
      Ok(rip_packet) => {
        // println!("PROCESSING RIP PACKET. \n COMMAND: {}\n", rip_packet.command);
        match rip_packet.command {
          // only send out to the person who requested
          1 => self.process_rip_request(packet),
          2 => self.process_rip_response(packet.src_ip, rip_packet.entries),
          _ => {
          // Handle unknown command
          eprintln!("Unknown RIP command: {}", rip_packet.command);
          }
        }
      }
      Err(e) => {
        eprintln!("RIP Message not formatted correctly! {}", e)
      }
    }
  }

  /*
    Creates and sends a rip response to the address of the router that requested.
   */
  pub fn process_rip_request(&mut self, packet: Packet) {
    // println!("PROCESSING THE RIP REQUEST. SENDING OUT RESPONSE HERE\n"); 
    // create the payload with the route information for interfaces that are enabled
    let mut entries: Vec<Entry> = Vec::new();
    for route in self.routing_table.get_routes(Some(self.rip_timeout_threshold.unwrap())) {
      // println!("THIS IS A ROUTE\n");
      // check if route has expired or cost is >= 16, then send RIP accordingly
      if route.cost.unwrap() >= 16 {
        let cost: u32 = route.cost.unwrap().into();
        let address = route.prefix.addr().to_bits();
        let mask = route.prefix.netmask().to_bits();
          let entry = Entry {
              cost: cost.clone(), 
              address: address.clone(), 
              mask: mask.clone(),
          };
          let rip_packet = RipPacket::new(2, 1, vec![entry]);
          // println!("Sending RIP packet to neighbors: {:?}", rip_packet);
          self.send_rip_to_neighbors(rip_packet);
          self.routing_table.remove_route(address, mask);
      } else if let NextHop::Interface(interface) = route.next_hop {
        if let Some(cost) = route.cost {
          entries.push(Entry { 
            cost: cost.into(), 
            address: interface.assigned_ip.to_bits(), 
            mask: interface.assigned_prefix.netmask().to_bits() 
          });
        }
      } else if let NextHop::RIPAddress(prefix) = route.next_hop {
        if let Some(cost) = route.cost {
          entries.push(Entry { 
            cost: cost.into(), 
            address: prefix.addr().to_bits(), 
            mask: prefix.netmask().to_bits() 
          });
        }
      }
    } 
    // println!("HELLO\n");
    let rip_packet = RipPacket::new(2, entries.len() as u16, entries);
    let packet = Packet::new(packet.dest_ip, packet.src_ip, 200, rip_packet.serialize_rip());
    // println!("Sending RIP packet to neighbor: {:?}", rip_packet);
    if let Some(next_route) =self.routing_table.lookup(packet.src_ip) {
      self.forward_packet(packet, next_route.next_hop.clone());
    }
  }
  
  pub fn send_rip_to_neighbors(&mut self, rip_packet: RipPacket) {
    // println!("SENDING RIP TO NEIGHBORS\n");
    if let Some(rip_neighbors) = &self.rip_neighbors {
        for rip_neighbor_ip in rip_neighbors {
            for neighbor in &self.neighbors {
                if neighbor.dest_addr == *rip_neighbor_ip { 
                    // CREATE NEW PACKET WITH THAT PAYLOAD AND EACH NEIGHBOR DEST_IP FOR HEADER
                    // specify the packet destination (header)
                    if let Some(next_route) = self.routing_table.lookup(neighbor.dest_addr) {
                      let packet = Packet::new(self.interfaces[0].config.assigned_ip,
                         *rip_neighbor_ip, 200, rip_packet.serialize_rip());
                        //  println!("RIP COMMAND: {}", rip_packet.command);
                      // println!("Neighbor: {:?}", *rip_neighbor_ip);
                      self.forward_packet(packet, next_route.next_hop.clone());
                    }
                }
            }
        }
    }
  }

  /*
    Updates the table in response to receiving a RIP response from a different router.
   */
  pub fn process_rip_response(&mut self, src_ip: Ipv4Addr, entries: Vec<Entry>) {
    // println!("OK IT IS PROCESSING THE RESPONSE.\n");

    // Collect valid RIP entries to send in one packet
    let mut valid_entries = Vec::new();

    for entry in entries {
        let cost = entry.cost;
        let is_invalid = cost >= 16;

        // Update the routing table regardless of valid or invalid route
        if let Some(updated_route) = self.routing_table.update_route(src_ip, entry) {
            // Create the RIP entry based on the updated route
            let entry = Entry {
                cost: updated_route.cost.unwrap().into(),
                address: updated_route.prefix.addr().to_bits(),
                mask: updated_route.prefix.netmask().to_bits(),
            };

            // Add the valid entry to the list if it's not invalid
            if !is_invalid {
                valid_entries.push(entry);
            }
        }
    }

    // After processing all entries, send a single RIP packet with valid routes
    if !valid_entries.is_empty() {
        let rip_packet = RipPacket::new(2, valid_entries.len() as u16, valid_entries);
        self.send_rip_to_neighbors(rip_packet);
    }
}

  // Process packets meant for the device (like a host would do)
  pub fn process_local_packet(&mut self, packet: Packet) {
      // println!("payload: {:?}", packet.payload);
      println!("Received test packet: Src: {}, Dst: {}, TTL: {}, Data: {}", 
          packet.src_ip, packet.dest_ip, packet.ttl, 
          String::from_utf8(packet.payload).unwrap());
  }

  // Helper to check if a packet is for a router (any of the router's interfaces)
  fn is_packet_for_device(&self, dest_ip: &Ipv4Addr) -> bool {
      for interface in &self.interfaces {
          if interface.config.assigned_ip == *dest_ip {
              return true; // This IP matches one of the router's interfaces
          }
      }
      false
  }

  fn find_interface_by_name(&self, interface_name: &str) -> Option<&InterfaceStruct> {
      self.interfaces.iter().find(|interface| interface.config.name == interface_name)
  }
  
  // Helper function to find the port of the neighbor's interface
  fn find_neighbor_socket(&self, matching_interface_struct: &InterfaceStruct) -> Option<(Ipv4Addr, u16)> {
    let interface_name = matching_interface_struct.config.name.clone(); // This should be a field in your struct
  
      // Iterate through the neighbors to find the matching interface based on IP address
      for neighbor in &self.neighbors {
          // Check if the neighbor's IP matches the interface's IP
          if neighbor.interface_name == interface_name {
              return Some((neighbor.udp_addr, neighbor.udp_port)); // Return the port number if a match is found
          }
      }
      None // Return None if no matching neighbor interface is found
  }

}