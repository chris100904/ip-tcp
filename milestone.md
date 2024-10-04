IP NOTES

IP Forwarding Table (Routing Table)
Functionality: Stores routes for packets based on destination IP dress and determines where packets should be forwarded. 

Implementation 
- Hashmap/dictionary where key —> value = IP address —> next hop/interface
    - The value could be some type of tuple or array to store the following info:
        - next hop
        - outgoing interface
        - metric (may or may not be needed for RIP, not sure)
- Trie/Prefix Tree
    - Much more efficient, but could be a bit more challenging to implement
    - Each node has children of either 0 or 1, and you would extend down from the root to check if the given IP address is a possible end path in the tree
    - ASSUMPTION: Trie/Prefix Tree is initially populated upon the start of the program in order to establish all connections between routers and hosts. 

ILLUSTRATION
ex. routing_table = {
    "124.001.0.0": ("127.0.0.1", "eth0"),  # Route to 127.0.0.1 via eth0
    "127.0.0.0": ("192.168.1.5", "eth1"),  # Route to 192.168.1.5 via eth1
}

Our goal is to send a packet from 124.001.0.0 to 192.168.1.5. We first check the hashmap for the destination by checking if 192.168.1.5 is a key in the hashmap. Since there’s no direct match, it falls back on 127.0.0.0. It forwards the packet to the 127.0.0.1 using the eth0 interface. The next router at 127.0.0.1 repeats this process for its own routing table, which then gets a matching entry for 192.168.1.5 and successfully forwards the packet to the right endpoint. 

Our goal is longest matching prefex to the destination from the source. This means that in the hashmap, we would potentially have to do an O(N) lookup to iterate through all the keys and find a match, which is extensive and unnecessary. Better option would be a trie. 

The trie would immediately search with the destination and search byte by byte until it’s not possible anymore. The ending node is the branch that we would need to go down (the interface we would send the data packets to). 

What will you do with a packet destined for local delivery (ie, destination IP == your node’s IP)?

Immediately forward the packet based on whatever protocol is specified. The design of the API should be that there shouldn’t necessarily have to be a differentiation between routing in local delivery versus non-local delivery, as there would always be sufficient checks of where to next send the data packets. In other words, since we want to abstract hosts vs. routers, the API should be general. 

STRUCTURE OF CODE:
- some general interface (struct)
    - host and router implements said interface (struct)
    - host and router will have their own host/router specific code as needed in their own structs

List of Functions for API (interface) 
- initialization
    - setting up the general routing table
        - can be a separate function itself
    - adding an interface
        - how to initialize an interface
- sending packets
    - UDP socket
- receiving packets
    - UDP socket
- protocol handler
    - handles different types of packets
    - test protocol
    - RIP protocol (only routers need it)
- check valid destination
    - check the routing table/trie to see if destination is valid
    - returns the next hop or error if not valid
- routing with RIP 
    - ??? 
- Listening
- Accepting
- Closing

What happens when a link is disabled? (ie, how is forwarding affected)?
- You would want to check for alternative routes (interfaces) that are allowed for that destination IP from the origin host/router via the routing table
- If there are no options, then you would want to drop the packet and return an error

