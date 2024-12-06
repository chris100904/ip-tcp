# TCP Project README

This document dives into the design choices Christopher Chen and Ethan Park made during the development of the TCP project.

## Questions

### 1. What are the key data structures that represent a connection?

       The key data structures that we use to represent a connection are the `SocketKey`, `Socket`, and `TcpSocket` structs. `SocketKey` is the struct containing local/remote IP addresses and ports, `Socket` is the struct holding socket_id, status (SocketStatus enum), and tcp_socket type, and `TcpSocket` is the enum that differentiates between Listener and Stream sockets. These structs are all initialized when a connection is made, and specifically the local/remote IP addresses represent, as the name implies, the local and remote connections that are used for the actual forwarding of the packets through IP protocol.

### 2. At a high level, how does your TCP logic (sending, receiving, retransmissions, etc.) use threads, and how do they interact with each other (and your data structures)? 

Here is a list of all of our threads:
1. REPL thread responsible for listening to command line prompts
2. Vhost and Vrouter thread responsible for calling all respective commands from the REPL thread
3. Vhost thread responsible for receiving packets
4. Listening thread for every listener initialized
5. For each socket, there is a thread responsible for sending tcp packets.
6. For each socket, there is a asynchronous retransmission thread.
7. A new thread gets made for teardown so there are no self dependencies for the code to complete.

When vhost gets initialized, threads 1, 2, and 3 are also created. Thread 1 directly communicates with 2 via channel and send a command enum. Thread 2 is created with the TCP object (struct data structure), calling commands that call the Arc Mutex protected version of the TCP object (we call it safe_tcp). Thread 3 is also created for the vhost to communicate with the tcp object so that the packet can be parsed in tcp.

When listen_and_accept() gets called, thread 4 gets created, which updates the socket_table object in the tcp struct. Thread 4 also contains the code for accept(), which is responsible for the handshake and the actual creation of the Socket objects. 

After accept() is called, threads 5 and 6 are created. Thread 5 accesses the TCP object (for overall socket_table information) and its own TCPStream socket object to update all necessary parameters. These parameters are also shared with thread 6. 

The communication between threads responsible for blocking receiving and sending (i.e., in the handshake) is handled largely via condition variables. Retransmission is handled with a VecDeque along with a condition variables. All shared data is wrapped in an Arc Mutex. The only instance where an object is not wrapped in an Arc Mutex in the TcpStream, TcpListener, Socket, or RTEntry objects is if the object is not ever mutated after initialization.

Thread 7 notifies all running threads to terminate processes.

### 3. If you could do this assignment again, what would you change? Any ideas for how you might improve performance?

Most of the project would’ve been the same. If we were to go about this again, we would’ve focused more on writing cleaner code and making sure to refactor code that might’ve been duplicated or redundant. On the grand scheme of the project, all the logic would’ve been roughly the same. One thing that we might want to try is to see if there are any alternatives to sending that didn’t require a separate sending thread. For example, maybe we could link the thread that is responsible for writing into the buffer to the sending thread to see if it would’ve helped the bug that we had in our final submission.

### 4. If you have any other major bugs or limitations not mentioned in the previous question, please describe the bug and how you have tried to debug the problem. 

       A bug that we have noted as of our final submission is that when our debugging print statements are deleted, testing with loss no longer works for some reason. We're not entirely sure why this is as it seems sort of counterintuitive (debugging statements should be increasing the latency...), but we did not proceed to debug this since we were running out of time.
       An additional bug we encountered was that our code can only successfully send the MB file if there is a 100 ms sleep in the sending thread. We have added extensive print statements, wireshark captures, cleaned up all lock waits and tried different RTOs but were still unable to figure out why the program was not able to handle a higher rate of sending bytes.

## Packet Capture

1. 3-way handshake
       Frames No. 1-3. The 3-way handshake is correct. Frame 1 shows the initial SYN that is sent. Frame 2 is the SYN/ACK sent by the listening socket. Frame 3 is the ACK sent back by the initiating socket.

2. One segment sent and acknowledged
       Frames No. 4 and No. 6. In Frame 4, the sender sends an ACK with SEQ=1 and ACK=1 of size 536 bytes. In Frame 6, the receiver sends an ACK acknowledging this packet with SEQ=537 and ACK=1, which is correct. 

3. One segment that is retransmitted
       Frames No. 287, 288, 292, 293, etc. (labeled TCP Retransmission). There is actually two sets of retransmissions happening here. First, Frames No. 287/288 retransmit the packet from SEQ=12329. At Frame No. 289, an ACK=15009 is received, which means that the sender can proceed. However, then another retransmission (Frames No. 292, 293) starting at SEQ=15009 starts. At Frame No. 294, an ACK=64857 is received, which is much bigger than our retransmission SEQ, so we can proceed normally. 

4. Connection teardown
       Frames No. 3929, 3930, and 3931. First, the sender sends a FIN which tells the receiver they are done sending packets. At 3930, the receiver sends an ACK acknowledging that FIN. Then, at 3931, a FIN is sent again by the receiver that tells the sender that they are also ready to initiate teardown. Once both sides are acknowledged, then teardown can proceed.