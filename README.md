# TCP Project README

This document dives into the design choices Christopher Chen and Ethan Park made during the development of the TCP project.

## Questions

### 1. What are the key data structures that represent a connection?

       The key data structures that we use to represent a connection are the `SocketKey`, `Socket`, and `TcpSocket` structs. `SocketKey` is the struct containing local/remote IP addresses and ports, `Socket` is the struct holding socket_id, status (SocketStatus enum), and tcp_socket type, and `TcpSocket` is the enum that differentiates between Listener and Stream sockets. These structs are all initialized when a connection is made, and specifically the local/remote IP addresses represent, as the name implies, the local and remote connections that are used for the actual forwarding of the packets through IP protocol.

### 2. At a high level, how does your TCP logic (sending, receiving, retransmissions, etc.) use threads, and how do they interact with each other (and your data structures)? 

### 3. If you could do this assignment again, what would you change? Any ideas for how you might improve performance?

### 4. If you have any other major bugs or limitations not mentioned in the previous question, please describe the bug and how you have tried to debug the problem. 

       The only bug that we have noted as of our final submission is that when our debugging print statements are deleted, testing with loss no longer works for some reason. We're not entirely sure why this is as it seems sort of counterintuitive (debugging statements should be increasing the latency...), but we did not proceed to debug this since we were running out of time.

## Packet Capture

1. 3-way handshake
       Frames No. 1-3. The 3-way handshake is correct. Frame 1 shows the initial SYN that is sent. Frame 2 is the SYN/ACK sent by the listening socket. Frame 3 is the ACK sent back by the initiating socket.

2. One segment sent and acknowledged
       Frames No. 4 and No. 6. In Frame 4, the sender sends an ACK with SEQ=1 and ACK=1 of size 536 bytes. In Frame 6, the receiver sends an ACK acknowledging this packet with SEQ=537 and ACK=1, which is correct. 

3. One segment that is retransmitted
       Frames No. 287, 288, 292, 293, etc. (labeled TCP Retransmission). There is actually two sets of retransmissions happening here. First, Frames No. 287/288 retransmit the packet from SEQ=12329. At Frame No. 289, an ACK=15009 is received, which means that the sender can proceed. However, then another retransmission (Frames No. 292, 293) starting at SEQ=15009 starts. At Frame No. 294, an ACK=64857 is received, which is much bigger than our retransmission SEQ, so we can proceed normally. 

4. Connection teardown
       Frames No. 3929, 3930, and 3931. First, the sender sends a FIN which tells the receiver they are done sending packets. At 3930, the receiver sends an ACK acknowledging that FIN. Then, at 3931, a FIN is sent again by the receiver that tells the sender that they are also ready to initiate teardown. Once both sides are acknowledged, then teardown can proceed.