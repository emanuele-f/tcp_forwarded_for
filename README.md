Objective: get original client source IP and port on a proxied TCP connection.

```
client [cli_ip:cli_port] -> [proxy_port] proxy [proxy_ip] -> [server_ip:server_port] server
```

We have a listening application on *server_port* and we want to retrieve
original *cli_ip:cli_port*. The proxy is using DNAT to proxy the connection, so
original client ip and ports are overwritten by the proxy_ip and a new port.

An initial idea was to use the TCP urgent pointer as a storage to set such
information in a trasparent way. However, this would require the server to open
a RAW socket in order to retrieve the TCP header data.

The current solution, instead, involves some cooperation from the client
application and requires a modification in the application protocol: the client sends
an additional 6 bytes data into the first data packet to the server (their content is not important).
Such bytes will be filled in by the proxy with client IP and port, thanks to a Netfilter hook.
The server can then handle the bytes as normal data and retrieve the original client
IP and port. This is akin to the *X-Forwarded-For* HTTP header used in HTTP proxies.

## Proxy configuration

We assume the proxy is configured as follows:

```
iptables -t nat -A PREROUTING -p tcp --dport 12345 -j DNAT --to-destination 1.2.3.4:22222
iptables -t nat -A POSTROUTING -p tcp --dport 22222 -d 1.2.3.4 -j MASQUERADE
iptables -t mangle -A POSTROUTING -p tcp --dport 22222 -d 1.2.3.4 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:3 -j NFQUEUE --queue-num 0 --queue-bypass
```

where:

  - `12345` is the *proxy_port*
  - `22222` is the *server_port*
  - `1.2.3.4` is the *server_ip*

The last line will enqueue packets on NFQUEUE 1 for the *proxy_rewriter* program.
The packet to be modified is the first one of the connection, so the `connbytes` filter
is used. NOTE: `connbytes` requires `net.netfilter.nf_conntrack_acct = 1`.

## Compiling

The `libnetfilter-queue-dev` and `libcap-dev` packages or equivalent are needed.

Run `make`. The program `proxy_rewriter` will be created.
