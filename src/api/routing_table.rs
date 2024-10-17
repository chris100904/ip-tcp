use std::{collections::HashMap, net::Ipv4Addr};
use super::parser::{IPConfig, InterfaceConfig, RoutingType};

pub struct Route {
  routing_mode: RoutingType,
  ip_addr: Ipv4Addr,
  prefix: u8,
  next_hop: InterfaceConfig,
  cost: u8,
}
// route_list: Vec<Route>,
pub struct Table {
  routing_table: HashMap<u8, HashMap<u32, InterfaceConfig>>,
  keys: Vec<u8>,
  routes: Vec<Route>,
}

impl Table {
  fn hash(ip_addr: &Ipv4Addr, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
      return 0;
    }
    let ip_u32 = u32::from(*ip_addr);
    let mask = !((1 << (32 - prefix_len)) - 1);
    ip_u32 & mask
  }

  fn sort_keys(routing_table: &HashMap<u8, HashMap<u32, InterfaceConfig>>) -> Vec<u8> {
    let mut keys: Vec<u8> = routing_table.keys().cloned().collect();
    keys.sort_unstable_by(|a, b| b.cmp(a));
    keys
  }

  pub fn new(&self, ip_config: &IPConfig) -> Self {
    let mut routing_table = HashMap::<u8, HashMap<u32, InterfaceConfig>>::new();
    let mut routes = Vec::new();
    for interface in &ip_config.interfaces {
      let prefix_len = interface.assigned_prefix.prefix_len();
      let hash = Table::hash(&interface.assigned_ip, prefix_len);
      let interface_clone = InterfaceConfig {
        name: interface.name.clone(),
        assigned_prefix: interface.assigned_prefix.clone(),
        assigned_ip: interface.assigned_ip.clone(),
        udp_addr: interface.udp_addr.clone(),
        udp_port: interface.udp_port.clone()
      };

      routing_table
        .entry(prefix_len)
        .or_insert_with(HashMap::new)
        .insert(hash, interface_clone);

      // Create a new Route object and add it to the routes vector
      let route = Route {
          routing_mode: RoutingType::Local, // or whatever routing type is applicable
          ip_addr: interface.assigned_ip,
          prefix: prefix_len,
          next_hop: interface_clone,
          cost: 0,
      };
      routes.push(route);
    }

    let keys = Table::sort_keys(&routing_table);

    Table { routing_table, keys, routes }
  }
  
  // add something to the table
  // pub fn add(&self, )

  // lookup something in the table
  pub fn lookup(&self, ip_addr: Ipv4Addr) -> Option<&InterfaceConfig> {
    for prefix in &self.keys {
        let hash = Table::hash(&ip_addr, *prefix);
        if let Some(ip_table) = self.routing_table.get(prefix) {
            if let Some(interface) = ip_table.get(&hash) {
                return Some(interface);
            }
        }
    }
    None
  }
}