# Snowcast Project README

This document dives into the design choices Christopher Chen and Ethan Park made during the development of the IP project.

## Design Choices

### 1. A major decision of ours was on what exactly to include in the shared API. In the end, we decided to abstract most of the functionality between Hosts and Routers. The only main differences that we distinguished between Hosts and Routers were the number of interfaces that they may have, as well as the Host/Router specific fields in the lnx file.
       Hosts and Routers are each treated as an implementation of a Device struct. We made the Host/Router specific fields as optional fields so that we can error handle properly for either Host or Router. Since the core functioanlity between Hosts and Routers were abstracted into shared components, we efficiently minimized code duplication.

### 2. The `NetworkInterface` struct is repsonsible for handling packet transmission and reception over UDP sockets. It manages both listening for incoming packets and sending them to other interfaces or devices. We established channels between the interfaces and their "parent device"; whenever a packet is received by the UDP socket,
       it gets forwarded up into the network layer (host and router in `device.rs`). From here, we abstract into the different functionalities of the device based on what type of packet and what type of protocol the packet was sent in. This is all handled within `device.rs`.

       The interface itself is defined as a InterfaceStruct, where we keep three fields: InterfaceConfig, bool enabled, and the actual `NetworkInterface`. We do this so that there is an easy place to access all general information that is needed of an interface.

### 3. In an attempt to create a more efficient routing table, we decided to create the table as a hashmap with hashmap values. The outer hashmap maps keys --> values in the form of prefix len --> hashmap. The inner hashmaps maps keys --> values in the form of IP address --> next hop. Whenever a lookup is done, the goal is to do longest prefix matching, so we iterate through the keys
       in descending order until we find a match for that lookup. Then, we consult the inner hashmap for the correct next hop. This way, we can guarantee to find the first next hop that is the longest prefix match.

## Questions

### 1. How did we build our abstractions for the IP layer and interfaces (What data structures do you have? How do your vhost and vrouter programs interact with your shared IP stack code?)
       The abstractions for the IP layer and interfaces were designed to maximize code reuse between the `vhost` and `vrouter` programs, while also allowing for the specific behavior needed by hosts and routers. Both Hosts and Routers are represented as implementations of a shared `Device` struct. This struct contains the basic functionality required for packet processing and interface management,
       which is common to both types of devices. The key difference between `vhost` and `vrouter` lies in the number of interfaces and the handling of routing tables. 

       Both hosts and routers can have one or more `NetworkInterface`s. Each interface handles communication over a virtual network using UDP sockets. Interfaces encapsulate the logic for receiving and sending packets. These interfaces also directly communicate with their parent device via a channel, where the Interfaces send through the channel and Devices receive and process that information.
       We employ Arc<Mutex<Device>> to ensure that the shared state of the device (like routing tables or interface statuses) is properly synchronized between threads. The `Device` struct also handles packet parsing, forwarding, and decision-making. Whether it's a host receiving a packet destined for it or a router forwarding the packet based on its routing table, the logic is shared in the core `Device` abstraction.

       Both `vhost` and `vrouter` programs rely on the shared IP stack code that provides the fundamental IP packet processing functionality, including packet parsing, forwarding decisions, and error handling. This shared IP stack consists of several core components that are abstracted and reused in both programs.

       - **Packet Structs**: IP packets are abstracted into a `Packet` struct that contains fields such as the IP header (source, destination, TTL, protocol, etc.) and the payload. Both `vhost` and `vrouter` utilize this struct to parse incoming IP packets and construct outgoing ones. This allows for consistent packet handling across both programs.
       
       - **Packet Handling Logic**: The core packet-handling logic is shared. In `vhost`, packets are either processed locally or dropped if they are not intended for the host. In `vrouter`, the packets are either processed locally or forwarded to another device based on routing table lookups. The decision-making process is abstracted into shared functions that handle IP forwarding, routing table lookups, and packet transmission.
       
       - **IP-in-UDP Encapsulation**: Both `vhost` and `vrouter` communicate with other devices using UDP sockets. The IP packets are encapsulated within UDP packets, simulating the behavior of a real network. The encapsulation and decapsulation logic are shared between both programs, allowing for seamless packet transmission over the virtual network.

       - **RIP Protocol (for vrouter)**: The routing logic in `vrouter` is further extended by the implementation of the RIP (Routing Information Protocol). `vrouter` uses RIP to exchange routing updates with neighboring routers, periodically sending route advertisements and updating its routing table based on received RIP responses. This dynamic routing capability allows routers to adapt to changes in the network topology and ensures proper forwarding of packets.

       - **Channels and Threads**: Both `vhost` and `vrouter` use channels to facilitate communication between their network interfaces and the device logic. Each `NetworkInterface` runs in its own thread, listening for incoming packets and sending them to the parent device for processing. The use of channels ensures that packets are transmitted between threads in a thread-safe manner, preventing race conditions and ensuring proper synchronization.

### 2. How do you use threads?
       Threads are spawned in the following places:
            - REPLs for `vrouter` or `vhost`. We spawn a thread to handle the command-line REPL. This thread listens for user commands and communicates with the main device via a channel, sending commands that modify or query the device's state. This ensures that the device continues processing packets in the background while still accepting commands interactively.
            - RIP Periodic Updates. In `vrouter`, a thread is created to handle the periodic sending of RIP updates. This thread sends updates automatically every "x" seconds without blocking the main execution. By spawning a separate thread for RIP, the router can handle routing updates and regular packet forwarding concurrently.
            - UDP Socket Communication. Each `NetworkInterface` runs its own thread to manage communication over UDP sockets. This design enables each interface to independently handle packet transmission and reception. When a packet is received by an interface, it is forwarded to its parent device (the `Device` struct) via a channel, where it can be processed appropriately. The use of threads ensures that packet handling is non-blocking,
              allowing the system to manage multiple interfaces simultaneously without bottlenecks.

### 3. What are the steps needed to process IP packets? 
       Let's assume that we have a Device A attempting to send a test packet to Device B. Firstly, the test packet needs to be encapsulated in the correct Packet structure that we specify. Then, the correct next hop needs to be identified. This is done through looking up the next hop through the routing/forwarding table with the destination IP. If there is a next hop that is specified, we send the packet through the next hop with the interface that is able to handle that IP address.
       This process of finding the correct interface is done through a loop in the `forward_packet` method. Once the correct interface is identified, we use that interface to send the packet to the next hop. This process continues until the packet eventually reaches the local subnet, or eventually reaches the destination IP and is handled locally. 

## Potential Bugs:
       The main bug that we have revolves around RIP. As of submission, we're unsure how to handle RIP when the next hop is an IPAdress vs. Interface. For example, let's say that we have H1-R1-R2-H2. After the initial RIP requests, the routing tables for R1 and R2 each have 3 entries: 2 have next hops of type Interface, and the other one has a next hop of type IPAddress. Before, we were only advertising the 2 entries that had type Interface because we knew how to obtain the mask (what is needed when we create an Entry). However, it's clear that we should be advertising everything, which includes the routes with the next hop of type IPAddress, but we're unsure how to obtain the mask in this case. 

       Although this is a bit of a stretch to conclude, most of the RIP logic should be the same besides the fact that we currently do not have a way of processing this. What we mean is that most of the underlying RIP logic is the same, and so if this is figured out, then the RIP protocol should be sufficient. 

       To duplicate this bug, we run the linear-r2h2 file and shut down both of the interfaces for any one of the routers. The updates don't propagate properly because we are not sending information about the RIP learned routes (since they have next hops of IPAddress). We're currently trying to solve this problem, but we ran out of time before the submission.