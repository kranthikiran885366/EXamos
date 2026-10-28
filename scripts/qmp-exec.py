#!/usr/bin/env python3
import socket
import json
import time
import sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/home/krant/sppio-test/qmp.sock')
s.recv(4096)
s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
s.recv(4096)

def send_key(key):
    msg = json.dumps({
        "execute": "send-key",
        "arguments": {"keys": [{"type": "qcode", "data": key}]}
    }) + "\n"
    s.sendall(msg.encode())
    s.recv(4096)

def send_combo(k1, k2, k3):
    msg = json.dumps({
        "execute": "send-key",
        "arguments": {"keys": [
            {"type": "qcode", "data": k1},
            {"type": "qcode", "data": k2},
            {"type": "qcode", "data": k3}
        ]}
    }) + "\n"
    s.sendall(msg.encode())
    s.recv(4096)

# 1. Switch to tty2
send_combo("ctrl", "alt", "f2")
time.sleep(1)

# Press enter
send_key("ret")
time.sleep(0.5)

# 2. Map characters to QMP qcodes
char_map = {
    ' ': 'spc',
    '\n': 'ret',
    '-': 'minus',
    '_': 'minus', # with shift
    '.': 'dot',
    '/': 'slash',
    ';': 'semicolon',
    '>': 'greater',
    ':': 'colon',
    '0': '0', '1': '1', '2': '2', '3': '3', '4': '4',
    '5': '5', '6': '6', '7': '7', '8': '8', '9': '9'
}

def type_text(text):
    for ch in text:
        if ch.isalpha():
            send_key(ch.lower())
        elif ch in char_map:
            send_key(char_map[ch])
        time.sleep(0.02)

cmd_to_run = "systemctl status examos-kiosk > /dev/ttyS0 ; journalctl -u examos-kiosk -n 50 --no-pager > /dev/ttyS0\n"
print("Typing command on tty2:", cmd_to_run)
type_text(cmd_to_run)
s.close()
print("Command sent successfully to guest tty2!")
