#!/bin/env python3
import socket
import sys
import struct
import random

PORT = 22222
REWRITE_ME_MAGIC = 0xF00DBEEF

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', PORT)

print("Connecting to %s:%d ..." % server_address)
sock.connect(server_address)

rand = random.randint(0, 0xFFFF)

# proxy data + payload
first_message = struct.pack('!IHH', REWRITE_ME_MAGIC, 0x0000, rand)
sock.sendall(first_message)

reply = struct.unpack('!H', sock.recv(2))[0]
assert (reply == rand+1)

last_message = struct.pack('!H', reply+1)
sock.sendall(last_message)

sock.close()
