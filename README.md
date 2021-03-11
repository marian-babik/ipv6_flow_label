

This repository provides notes on the IPV6 FLOWLABEL implementation in the Linux kernel together with references and some sample code.

The code was tested on Fedora 33 (kernel 5.8.15-301). The following sysctl settings were used (see below for explanation):
```
# /proc/sys/net/ipv6/flowlabel_reflect -> 1
# /proc/sys/net/ipv6/flowlabel_consistency -> 0
# /proc/sys/net/ipv6/auto_flowlabels -> 0
# /proc/sys/net/ipv6/flowlabel_state_ranges -> 0
```

To run a simple IPv6 TCP flow label exercise, compile using:
```
# gcc client.c -o client
# gcc -pthread server.c -o serve
```
To run (server will bind to all interfaces and will listen on port 24999):
```
# ./server
# ./client <ipv6_addr_of_server>
```

Note that this only works on IPv6 enabled machines. 

To check the traffic you can use e.g. tshark like this:
```
# tshark -i veth0 -f "ip6" -T fields -e frame.number -e frame.time_delta -e ipv6.src -e ipv6.dst \
  -e tcp.port -e ipv6.flow -e ipv6.tclass.dscp
```

You can check what existing flow labels are tracked by the system via:
```
# cat /proc/net/ip6_flowlabel
Label S Owner  Users  Linger Expires  Dst                              Opt
000FF 255 0      0      6      5      <dst_addr>                       0
```

To run a simple IPv6 UDP flow label exercise, which implements simple reflection, compile using:
```
# gcc udp_server.c -o udp_server
# gcc udp_client.c -o udp_client
```

To run:
```
# ./udp_client <server_addr>
# ./udp_server
```

**Documentation**

***History***

Initial implementation by Alexey Kuznetsov in kernel 2.2.7 (April 1999)
- Official documentation is at http://linux-ip.net/gl/api-ip6-flowlabels/api-ip6-flowlabels.html
This was based on RFC 1809 and RFC 2460, which had a number of restrictions (in Appendix A): 
- Just one label per destination
- All sockets with given label must share same extension headers
- Labels must have finite lifetime (expiration time) and can’t be re-used right away (linger time); 

Since then mostly maintenance changes ([commit history](https://github.com/torvalds/linux/commits/master?before=dcc0b49040c70ad827a7f3d58a21b01fdb14e749+35&branch=master&path%5B%5D=net&path%5B%5D=ipv6&path%5B%5D=ip6_flowlabel.c)), but there were also some new features added:
- Tom Herbert - Auto flow labels - automatically generate flow labels based on a flow hash of the packet (RFC 6437; and this [talk](https://datatracker.ietf.org/meeting/110/materials/slides-110-v6ops-tcp-socket-hash-flow-label-00))
- Florent Fourcot removed some of the historical restrictions (following RFCs 3697/6437) and added flow label reflections; first commits were in kernel 3.11 (2014)
- Tom Herbert - split label space into two ranges, one for auto labels and the other for the original usage (motivated by RFC 6438)

***Implementation***

Flow labels are managed via socket option IPV6_FLOWLABEL_MGR, which implements a sophisticated mechanism to ensure system wide policy. Some of its important attributes are following:
```
label   - flow label to set/get
action  - one of get/put/renew/remote - this is used to acquire new label, release \
          it, renew it 
share   - controls how flow labels can be shared with other processes (any, none\
          exclusive, process, etc)
expires - determines label lease time
linger  - time for given label to be available again once it expires
```

The basic usage is to 1. enable flow labels via option IPV6_FLOWINFO_SEND, 2. request a label via manager and then 3. assign the label to the socket (and optionally 4. releasing the flow label).
```
struct sockaddr_in6 *dst
struct in6_flowlabel_req freq;


1. setsockopt(fd, SOL_IPV6, IPV6_FLOWINFO_SEND, 1)                     
freq.flr_label = <label_to_set>;
freq.flr_action = IPV6_FL_A_GET;
freq.flr_share = IPV6_FL_S_ANY;
2. setsockopt(fd, SOL_IPV6, IPV6_FLOWLABEL_MGR,freq)

3. dst->sin6_flowinfo = freq.flr_label;

freq.flr_action = IPV6_FL_A_PUT;  (4. optionally release the flow label)
setsockopt(fd, SOL_IPV6, IPV6_FLOWLABEL_MGR, freq)
```

***TCP details***

This works on the client side (for both TCP and UDP), but not on the server side. Likely because flow is already established once server accept() is reached.

Socket option IPV6_FL_F_REFLECT, motivated by RFC7690, will reflect incoming flows labels in the outgoing packets.

Can be enabled via flow manager or directly via sysctl (only TCP, ICMP)

Reading flow labels:
- Using sysctl, via /proc/net/ipv6/ip6_flowlabel
  - Can be also accessed via flow manager by calling getsockopt() using action IPV6_FL_A_GET
  - Returns all local flow labels - system wide (also works with reflection enabled)
- Using flow manager and action IPV6_FL_A_REMOTE
  - Returns remote flow label - flow label on the incoming packets (Note: didn’t work for me in the tests, possible conversion issue or a bug)

***UDP details***

UDP works the same way for the client, but not on the server (reflection is TCP only feature), however UDP has a simpler interface and it’s easier to get access to the ancillary data when overriding default calls (sendto/recvfrom).

UDP client/server examples are using ancillary data to set/get/change/reflect labels as needed. 

***SYSCTL settings***
https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt

```
flowlabel_consistency - BOOLEAN
	Protect the consistency (and unicity) of flow label.
	You have to disable it to use IPV6_FL_F_REFLECT flag on the
	flow label manager.
	TRUE: enabled
	FALSE: disabled
	Default: TRUE

auto_flowlabels - INTEGER
	Automatically generate flow labels based on a flow hash of the
	packet. This allows intermediate devices, such as routers, to
	identify packet flows for mechanisms like Equal Cost Multipath
	Routing (see RFC 6438).
	0: automatic flow labels are completely disabled
	1: automatic flow labels are enabled by default, they can be
	   disabled on a per socket basis using the IPV6_AUTOFLOWLABEL
	   socket option
	2: automatic flow labels are allowed, they may be enabled on a
	   per socket basis using the IPV6_AUTOFLOWLABEL socket option
	3: automatic flow labels are enabled and enforced, they cannot
	   be disabled by the socket option
	Default: 1

flowlabel_state_ranges - BOOLEAN
	Split the flow label number space into two ranges. 0-0x7FFFF is
	reserved for the IPv6 flow manager facility, 0x80000-0xFFFFF
	is reserved for stateless flow labels as described in RFC6437.
	TRUE: enabled
	FALSE: disabled
	Default: true

flowlabel_reflect - INTEGER
	Control flow label reflection. Needed for Path MTU
	Discovery to work with Equal Cost Multipath Routing in anycast
	environments. See RFC 7690 and:
	https://tools.ietf.org/html/draft-wang-6man-flow-label-reflection-01

	This is a bitmask.
	1: enabled for established flows

	Note that this prevents automatic flowlabel changes, as done
	in "tcp: change IPv6 flow-label upon receiving spurious retransmission"
	and "tcp: Change txhash on every SYN and RTO retransmit"

	2: enabled for TCP RESET packets (no active listener)
	If set, a RST packet sent in response to a SYN packet on a closed
	port will reflect the incoming flow label.

	4: enabled for ICMPv6 echo reply messages.

	Default: 0

  seg6_flowlabel - INTEGER
	Controls the behaviour of computing the flowlabel of outer
	IPv6 header in case of SR T.encaps

	-1 set flowlabel to zero.
	0 copy flowlabel from Inner packet in case of Inner IPv6
		(Set flowlabel to 0 in case IPv4/L2)
	1 Compute the flowlabel using seg6_make_flowlabel()

	Default is 0.
```



