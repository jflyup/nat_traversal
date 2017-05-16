# nat_traversal
A implementation of this paper: [A New Method for Symmetric NAT Traversal in UDP and TCP](http://www.goto.info.waseda.ac.jp/~wei/file/wei-apan-v10.pdf)  
According to [RFC 3489](http://tools.ietf.org/html/rfc3478), a symmetric NAT is one where all requests from the same internal IP address and port, to a specific destination IP address and port, are mapped to the same external IP address and
port. If the same host sends a packet with the same source address and port, but to a different destination, a different mapping is used. Furthermore, only the external host that receives a packet can send a UDP packet back to the internal host.  
So, if we know the port allocation rule of the Symmetric NAT, we can traverse Symmetric NAT. This paper proposes a new method for traversing Symmetric NAT which is based on port prediction and limited TTL values.  
## Usage
***  
It's just a experience project, I just wanna test whether UDP punching is possible if both nodes are behind symmetric NAT. It works this way:  

A peer got its own NAT info(external ip/port, NAT type ), then registers to server, the server replies to the peer with a unique peer ID. if you specify `-d peer ID` option, the node tries to get the info of that specified peer from the server, then connects to it directly. So when you specify '-d' option, make sure that peer is connected with server.  

To run it, you should run `punch_server.go` in a machine with public IP, so both nodes can connect to it to exchange info(just node info, not to relay payload like [RFC 6062](https://tools.ietf.org/html/rfc6062)), then run `nat_traversal [-s punch server] [-d if you wanna connect to peer]` on clients, you can also specify other arguments, such as, STUN server by `-H` option, source IP by `-i`, source port by `-p`.  
This program is not 100% guaranteed to make 2 peers behind symmetric NATs connect
to each other directly, it's theoretically possible. Actually, I just happen to succeed once. Hope more people can test it.