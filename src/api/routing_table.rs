use std::{collections::HashMap, net::Ipv4Addr};
use ipnet::{IpNet, Ipv4Net};
use std::time::{Duration, Instant};

use super::{packet::Entry, parser::{IPConfig, InterfaceConfig, RoutingType}};

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
  pub last_updated: Instant,
}

impl Route {
  pub fn clone(&self) -> Route {
    return Route {
      routing_mode: self.routing_mode.clone(),
      prefix: self.prefix.clone(),
      next_hop: self.next_hop.clone(),
      cost: self.cost.clone(),
      last_updated: Instant::now()
    }
  }
}
// route_list: Vec<Route>,

#[derive(Debug)]
pub struct Table {
  // Prefix_len -> Hashed-IP (after mask) -> Route
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
        last_updated: Instant::now(),
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
        last_updated: Instant::now(),
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

  pub fn get_routes(&mut self, timeout: Option<u64>) -> Vec<Route> {
    let mut routes: Vec<Route> = Vec::new();
    let prefixes: Vec<u8> = self.routing_table.keys().cloned().collect();
    for prefix in prefixes {
      if let Some(route_map) = self.routing_table.get_mut(&prefix) {
        let hashes: Vec<u32> = route_map.keys().cloned().collect();
        for hash in hashes {
          if let Some(route) = route_map.get_mut(&hash) {
            if let Some(expiration_secs) = timeout {
                let now = Instant::now();
                let expiration_time = Duration::from_secs(expiration_secs);
                if now.duration_since(route.last_updated) > expiration_time {
                    // Route has expired, set its cost to infinity (16)
                    route.cost = Some(16);
                }
            }
            routes.push(route.clone());
          }
        }
      }
    }
    return routes;
  }

  // // check if anything has expired
  // pub fn get_expired_routes(&mut self) -> Vec<u32>{
  //       let expiration_time = Duration::from_secs(12); // 12 seconds expiration time
  //       let now = Instant::now();
  //       let mut expired_routes = Vec::new();
  //       // Iterate over all routes and check for expiration
  //       for (prefix_len, route_map) in self.routing_table.iter_mut() {
  //           for (hash, route) in route_map {
  //               if now.duration_since(route.last_updated) > expiration_time {
  //                   // Route has expired, set its cost to infinity (16)
  //                   route.cost = Some(16);
  //                   expired_routes.push(*hash); // Mark route for removal after RIP update
                    
  //               }
  //           }

  //           // // Optionally remove expired routes or handle them accordingly (e.g., trigger RIP update)
  //           // for hash in expired_routes {
  //           //     route_map.remove(&hash);
  //           // }
  //       }
  //       return expired_routes;
  //   }

  // Function to determine if a route should be advertised based on Split Horizon
  pub fn should_advertise(&self, route: &Route, source: &NextHop) -> bool {
      // Logic to determine if the route should be advertised back to the source
      match &route.next_hop {
          NextHop::Interface(interface) => {
              // Check if the source is the same interface (prevent advertising back)
              if let NextHop::Interface(src_interface) = source {
                  return interface != src_interface;
              }
          }
          NextHop::IPAddress(ip_addr) => {
              // Prevent advertising back to the source IP address
              if let NextHop::IPAddress(src_ip) = source {
                  return ip_addr != src_ip;
              }
          }
      }
      true // Advertise if it doesn't match
    }
  
  pub fn add_route(&mut self, address: u32, mask: u32, route: Route){
    let ip = Ipv4Addr::from(address);
    let prefix_len: u8 = mask.count_ones().try_into().unwrap();
    let hash = Table::hash(&ip, prefix_len);

    self.routing_table.entry(prefix_len)
      .or_insert_with(HashMap::new)
      .insert(hash, route);
  }

  pub fn remove_route(&mut self, dest_address: u32, dest_mask: u32) -> Option<Route> {
    let ip = Ipv4Addr::from(dest_address);
    let prefix_len: u8 = dest_mask.count_ones().try_into().unwrap();
    let hash = Table::hash(&ip, prefix_len);

    if let Some(route_map) = self.routing_table.get_mut(&prefix_len) {
      let route = route_map.remove(&hash);
      println!("Removed Route: {:?}", route);

      if route_map.is_empty() {
        self.routing_table.remove(&prefix_len);
        self.keys = Table::sort_keys(&self.routing_table);
      }
      return route
    }
    None
  }

  pub fn update_route(&mut self, src_ip: Ipv4Addr, entry: Entry) -> Option<&Route> {
    let ip = Ipv4Addr::from(entry.address);
    let prefix_len: u8 = entry.mask.count_ones().try_into().unwrap();
    let hash = Table::hash(&ip, prefix_len);
    let cost = u8::try_from(entry.cost).unwrap();
    let prefix = Ipv4Net::new(ip, prefix_len).unwrap();
    
    let mut route: Route = Route { 
      routing_mode: RoutingType::Rip, 
      prefix, 
      next_hop: NextHop::IPAddress(src_ip), 
      cost: Some(cost + 1),
      last_updated: Instant::now(),
    };
    
    // Check if the route exists in the table
    if let Some(route_map) = self.routing_table.get_mut(&prefix_len) {
        if let Some(existing_route) = route_map.get_mut(&hash) {
            // If the route exists, compare the cost
            if let Some(existing_cost) = existing_route.cost {
              if let Ok(new_cost) = u8::try_from(entry.cost) {
                if new_cost + 1 <= existing_cost {
                  println!("Updating Route: {:?} from Route: {:?}", route, existing_route);
                  route_map.get_mut(&hash).replace(&mut route);
                } else {
                  return None;
                }
              }
            }
        } else {
          if !self.should_advertise(&route, &NextHop::IPAddress(src_ip)) {
            // If Split Horizon applies, USE COST OF INFINITY  
            route.cost = Some(16);
          }
          println!("Adding Route: {:?}", route);
          self.add_route(entry.address, entry.mask, route);
        }
    } else {
        // If the prefix length key does not exist, create it and add the route
        println!("Adding Route: {:?}", route);
        self.add_route(entry.address, entry.mask, route);
    }
    // Update keys after adding a new route
    self.keys = Table::sort_keys(&self.routing_table);
    return Some(&self.routing_table.get(&prefix_len).unwrap().get(&hash).unwrap());
  }
}