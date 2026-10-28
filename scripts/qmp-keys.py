#!/usr/bin/env python3
import socket
import json
import time

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/home/krant/sppio-test/qmp.sock')
s.recv(4096)
s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
s.recv(4096)

# Send Ctrl+Alt+F2
key_cmd = json.dumps({
    "execute": "send-key",
    "arguments": {
        "keys": [
            {"type": "qcode", "data": "ctrl"},
            {"type": "qcode", "data": "alt"},
            {"type": "qcode", "data": "f2"}
        ]
    }
}) + "\n"
s.sendall(key_cmd.encode())
print("F2 sent:", s.recv(4096).decode())
time.sleep(1)

# Screendump
s.sendall(json.dumps({
    "execute": "screendump",
    "arguments": {"filename": "/home/krant/sppio-test/screen.ppm"}
}).encode() + b"\n")
print("Screendump:", s.recv(4096).decode())
s.close()
