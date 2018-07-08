#!/bin/env python3
import socket
import sys
import struct

PORT = 22222

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('localhost', PORT)
sock.bind(server_address)
sock.listen(1)

print("Listening on %s:%d" % server_address)

while True:
  client, client_address = sock.accept()
  print("Connection from %s:%d" % client_address)

  orig_ip, orig_port, data = struct.unpack('!IHH', client.recv(8))

  if orig_ip and orig_port:
    print("Original client address: %s:%d" % (socket.inet_ntoa(struct.pack('!I', orig_ip)), orig_port))

  print("< %d" % data)

  client.sendall(struct.pack('!H', data+1))
  print("> %d" % (data+1))

  print("< %d" % struct.unpack('!H', client.recv(2)))
