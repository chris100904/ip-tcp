use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

#[derive(Debug)]
struct TrieNode {
    children: HashMap<bool, TrieNode>,
    interface: Option<NetworkInterface>,
}

#[derive(Debug)]
pub struct RoutingTrie {
    root: TrieNode,
}

impl RoutingTrie {
    /// Create a new empty RoutingTrie
    pub fn new() -> Self {
        RoutingTrie { root: TrieNode { children: HashMap::new(), interface: None } }
    }

    /// Insert a route into the Trie
    ///
    /// # Arguments
    ///
    /// * `destination`: The destination IP address of the route
    /// * `prefix_length`: The length of the prefix in bits
    /// * `interface`: The interface the route should be routed to
    ///
    /// # Returns
    ///
    /// Returns a Result with an Error if the route couldn't be inserted.
    pub fn insert(&mut self, destination: Ipv4Addr, prefix_length: usize, interface: NetworkInterface) -> Result<(), Error> {
        let mut node = &mut self.root;
        let bits = Self::ip_to_bits(destination);
        
        // Iterate over the bits of the destination IP address
        for i in 0..prefix_length {
            let bit = bits[i];
            // If the bit is not already in the children map, insert a new child
            node = node.children.entry(bit).or_insert_with(|| TrieNode {
                children: HashMap::new(),
                interface: None,
            });
        }
        
        // Store the interface at the end of the prefix
        node.interface = Some(interface);
        Ok(())
    }

    /// Lookup a route in the Trie
    ///
    /// # Arguments
    ///
    /// * `destination`: The destination IP address to look up
    ///
    /// # Returns
    ///
    /// Returns an Option containing a reference to the interface if found, None if not found
    pub fn lookup(&self, destination: Ipv4Addr) -> Option<&NetworkInterface> {
        let bits = Self::ip_to_bits(destination);
        let mut node = &self.root;

        // Iterate over the bits of the destination IP address
        for bit in bits {
            if let Some(child) = node.children.get(&bit) {
                node = child;
            } else {
                break;
            }
        }

        // Return the interface, if found
        node.interface.as_ref()
    }

    /// Remove a route from the Trie
    ///
    /// # Arguments
    ///
    /// * `destination`: The destination IP address of the route to remove
    /// * `prefix_length`: The length of the prefix in bits
    ///
    /// # Returns
    ///
    /// Returns a Result with an Error if the route couldn't be removed.
    pub fn remove(&mut self, destination: Ipv4Addr, prefix_length: usize) -> Result<(), Error> {
        let mut node = &mut self.root;
        let bits = Self::ip_to_bits(destination);
        
        // Iterate over the bits of the destination IP address
        for i in 0..prefix_length {
            let bit = bits[i];
            if let Some(child) = node.children.get_mut(&bit) {
                node = child;
            } else {
                return Err(Error::new(ErrorKind::NotFound, format!("No route found for destination IP: {}", destination)));
            }
        }
        
        // Remove the interface at the end of the prefix
        node.interface = None;
        Ok(())
    }

    /// Convert IP address to a vector of bits (0 and 1)
    fn ip_to_bits(ip: Ipv4Addr) -> Vec<bool> {
        let mut bits = Vec::new();
        let octets = ip.octets();

        // Iterate over the octets of the IP address
        for &octet in &octets {
            // Iterate over the bits of the octet
            for i in (0..8).rev() {
                // Push true for 1 and false for 0
                bits.push((octet >> i) & 1 == 1);
            }
        }
        
        bits
    }
}