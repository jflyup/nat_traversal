# nat_traversal
A implementation of this paper: [A New Method for Symmetric NAT Traversal in UDP and TCP](http://www.goto.info.waseda.ac.jp/~wei/file/wei-apan-v10.pdf)  
According to [RFC 3489](http://tools.ietf.org/html/rfc3478), a symmetric NAT is one where all requests from the same internal IP address and port, to a specific destination IP address and port, are mapped to the same external IP address and
port. If the same host sends a packet with the same source address and port, but to a different destination, a different mapping is used. Furthermore, only the external host that receives a packet can send a UDP packet back to the internal host.  
So, if we know the port allocation rule of the Symmetric NAT, we can traverse Symmetric NAT. This paper proposes a new method for traversing Symmetric NAT which is based on port prediction and limited TTL values.
