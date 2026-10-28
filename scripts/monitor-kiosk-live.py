#!/usr/bin/env python3
import socket
import json
import zlib
import struct
import time
import sys
import os

qmp_sock_path = "/home/krant/sppio-test/qmp.sock"
ppm_path = "/home/krant/sppio-test/screen.ppm"
png_path = "/home/krant/sppio-test/screen.png"
windows_path = "/mnt/c/Users/krant/.gemini/antigravity/brain/a1f377ff-ef8e-4e49-ba0c-3e0779e27801/qemu-screen.png"

print("=== Waiting for QMP socket to appear ===")
start = time.time()
while time.time() - start < 60:
    if os.path.exists(qmp_sock_path):
        break
    time.sleep(1)

if not os.path.exists(qmp_sock_path):
    print("FAIL: QMP socket did not appear")
    sys.exit(1)

def dump_screen():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(qmp_sock_path)
    s.recv(4096)
    s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
    s.recv(4096)
    s.sendall(json.dumps({"execute": "screendump", "arguments": {"filename": ppm_path}}).encode() + b"\n")
    s.recv(4096)
    s.close()

    with open(ppm_path, "rb") as f:
        header = f.readline().strip()
        line = f.readline().strip()
        while line.startswith(b"#"):
            line = f.readline().strip()
        parts = line.split()
        if len(parts) == 2:
            w, h = int(parts[0]), int(parts[1])
            f.readline()
        else:
            w, h = int(parts[0]), int(parts[1])
        data = f.read()

    total = len(data)
    non_zero = sum(1 for b in data if b != 0)
    return w, h, total, non_zero, data

def save_png(width, height, rgb_data, filename):
    raw = bytearray()
    row_bytes = width * 3
    for y in range(height):
        raw.append(0)
        raw.extend(rgb_data[y * row_bytes : (y + 1) * row_bytes])
    compressed = zlib.compress(bytes(raw), 9)

    def png_chunk(t, d):
        c = t + d
        crc = struct.pack(">I", zlib.crc32(c) & 0xffffffff)
        return struct.pack(">I", len(d)) + c + crc

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png.extend(png_chunk(b"IHDR", ihdr))
    png.extend(png_chunk(b"IDAT", compressed))
    png.extend(png_chunk(b"IEND", b""))

    with open(filename, "wb") as f:
        f.write(png)

print("=== Monitoring QEMU Screen (polling every 5s up to 120s) ===")
poll_start = time.time()
ui_detected = False
while time.time() - poll_start < 120:
    try:
        w, h, total, non_zero, data = dump_screen()
        pct = (non_zero / total) * 100 if total > 0 else 0
        elapsed = int(time.time() - poll_start)
        print(f"[{elapsed}s] Screen: {w}x{h}, Non-zero pixels: {non_zero}/{total} ({pct:.2f}%)")

        save_png(w, h, data, png_path)
        try:
            with open(png_path, "rb") as s_f, open(windows_path, "wb") as d_f:
                d_f.write(s_f.read())
        except Exception:
            pass

        # Check for substantial graphics after at least 15s of boot (past UEFI)
        if elapsed > 15 and pct > 5.0:
            print(f"\n[ACTIVE UI DETECTED] Screen: {w}x{h}, {pct:.2f}% active pixels!")
            ui_detected = True
            # Keep monitoring for a few more seconds to capture the full Chromium render
            if elapsed > 35:
                print("UI fully stabilized. Done.")
                break
    except Exception as e:
        print(f"Polling error: {e}")
    time.sleep(5)

print("Monitor finished.")
