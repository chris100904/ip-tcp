use std::{collections::HashMap, net::Ipv4Addr};
use ipnet::Ipv4Net;

use super::parser::{IPConfig, InterfaceConfig, RoutingType};

#[derive(Debug, Clone)]
pub enum NextHop {
  Interface(InterfaceConfig),
  IPAddress(Ipv4Addr)
}

impl NextHop {
  pub fn clone(&self) -> NextHop {
    match self {
      NextHop::IPAddress(addr) => return NextHop::IPAddress(addr.clone()),
      NextHop::Interface(interface) => return NextHop::Interface(interface.clone())
    }
  }
}

#[derive(Debug, Clone)]
pub struct Route {
  pub routing_mode: RoutingType,
  pub prefix: Ipv4Net,
  pub next_hop: NextHop,
  pub cost: Option<u8>,
}

impl Route {
  pub fn clone(&self) -> Route {
    return Route {
      routing_mode: self.routing_mode.clone(),
      prefix: self.prefix.clone(),
      next_hop: self.next_hop.clone(),
      cost: self.cost.clone()
    }
  }
}
// route_list: Vec<Route>,

#[derive(Debug)]
pub struct Table {
  pub routing_table: HashMap<u8, HashMap<u32, Route>>,
  pub keys: Vec<u8>,
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

  fn sort_keys(routing_table: &HashMap<u8, HashMap<u32, Route>>) -> Vec<u8> {
    let mut keys: Vec<u8> = routing_table.keys().cloned().collect();
    keys.sort_unstable_by(|a, b| b.cmp(a));
    keys
  }

  pub fn new(ip_config: &IPConfig) -> Self {
    let mut routing_table = HashMap::<u8, HashMap<u32, Route>>::new();
    for interface in &ip_config.interfaces {
      let prefix_len = interface.assigned_prefix.prefix_len();
      let hash = Table::hash(&interface.assigned_ip, prefix_len);

      // Create a new Route object and add it to the routes vector
      let route = Route {
        routing_mode: RoutingType::None, // or whatever routing type is applicable
        prefix: interface.assigned_prefix,
        next_hop: NextHop::Interface(interface.clone()),
        cost: Some(0),
    };

      routing_table
        .entry(prefix_len)
        .or_insert_with(HashMap::new)
        .insert(hash, route);
    }

    for static_route in &ip_config.static_routes {
      let prefix_len = static_route.0.prefix_len();
      let hash = Table::hash(&static_route.0.addr(), prefix_len);
      
      let route = Route {
        routing_mode: RoutingType::Static, // or whatever routing type is applicable
        prefix: static_route.0,
        next_hop: NextHop::IPAddress(static_route.1),
        cost: None,
      };

      routing_table
        .entry(prefix_len)
        .or_insert_with(HashMap::new)
        .insert(hash, route);
    }

    let keys = Table::sort_keys(&routing_table);
    
    Table { routing_table, keys }
  }
  
  // add something to the table
  // pub fn add(&self, )

  // lookup something in the table
  pub fn lookup(&self, ip_addr: Ipv4Addr) -> Option<&Route> {
    for prefix in &self.keys {
      let hash = Table::hash(&ip_addr, *prefix);
      if let Some(ip_table) = self.routing_table.get(prefix) {
        if let Some(route) = ip_table.get(&hash) {
          return Some(route);
        }
      }
    }
    None
}

  pub fn get_routes(&self) -> Vec<Route> {
    let mut routes: Vec<Route> = Vec::new();
    for prefix in self.routing_table.keys() {
      if let Some(route_map) = self.routing_table.get(prefix) {
        for hash in route_map.keys() {
          if let Some(route) = route_map.get(hash) {
            routes.push(route.clone());
          }
        }
      }
    }
    return routes;
  }

  pub fn ez_lookup<'a>(routing_table: &'a HashMap<u8, HashMap<u32, Route>>, 
    keys: &'a Vec<u8>, ip_addr: Ipv4Addr) -> Option<&'a Route> {
    for prefix in keys {
        let hash = Table::hash(&ip_addr, *prefix);
        if let Some(ip_table) = routing_table.get(prefix) {
            if let Some(interface) = ip_table.get(&hash) {
                return Some(interface);
            }
        }
    }
    None
  }
}