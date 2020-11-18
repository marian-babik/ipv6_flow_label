
```
A simple IPv6 flow label exercise, to compile run:
# gcc client.c -o client
# gcc -pthread server.c -o serve

To run (server will bind to all interfaces and will listen on port 24999):
# ./client <ipv6_of_server>
# ./server

Only works on IPv6 enabled machines. More examples TBA.

To check the traffic you can use e.g. tshark like this:
# tshark -i lo -f "ip6 and port 24999" -T fields -e frame.number -e frame.time_delta \
  -e ipv6.src -e ipv6.dst -e ipv6.flow
```

