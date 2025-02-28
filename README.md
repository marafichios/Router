# Router

This homework aims to implement a simple router in C, which intercepts packets
from the corresponding interfaces and manages to forward them.

I have managed to work with the IP packet forwarding, ICMP error handling, ARP
table and finding the longest prefix match.

Short description:
* When the router receives a packet, the Ethernet header is analyzed to check 
whether the packet has an IP header. The checksum and TTL are also verified
to ensure that the packet is valid, if not, it is dropped (if the ttl is <= 1
and if the checksum of the IP header doesnt match the one calculated).
If valid, the TTL is decremented and the checksum is recalculated, meaning the
packet is ready to be forwarded. Then a best route is searched with the help of
the function get_best_route, which returns the longest prefix match. If no way
is found, an ICMP error message is sent with the help of the function send_icmp_error.
If a route is found, there also need to be found the MAC adress of the next hop and
that is done within the ARP table. Then the source and destination MAC adresses are
changed so that they can represent the router and the next hop. Then the packet is
sent on the corresponding interface.

* The icmp error message function sets the ICMP based on the error type, meaning 3
is for unreachabele destination and 11 is for TTL exceeded. The function also sets
the IP header and the ICMP header. Also, within the handle_ip function, there is
checker whether the packet is an ICMP echo request which stands for 8 and it creates
an echo reply message which stands for 0.

