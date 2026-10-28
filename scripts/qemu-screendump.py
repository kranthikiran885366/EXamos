#!/usr/bin/env python3
import socket
import json
import zlib
import struct
import sys
import os

qmp_sock_path = "/home/krant/sppio-test/qmp.sock"
ppm_path = "/home/krant/sppio-test/screen.ppm"
png_path = "/home/krant/sppio-test/screen.png"
artifact_png = "C:/Users/krant/.gemini/antigravity/brain/a1f377ff-ef8e-4e49-ba0c-3e0779e27801/qemu-screen.png"

if not os.path.exists(qmp_sock_path):
    print(f"Error: QMP socket {qmp_sock_path} does not exist. Is QEMU running with -qmp?")
    sys.exit(1)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(qmp_sock_path)

def send_qmp(obj):
    msg = json.dumps(obj) + "\n"
    s.sendall(msg.encode())
    res = ""
    while True:
        chunk = s.recv(4096).decode('utf-8', errors='ignore')
        res += chunk
        if "\n" in chunk:
            break
    return res

# 1. Read greeting
greeting = s.recv(4096).decode('utf-8', errors='ignore')

# 2. Capabilities handshake
send_qmp({"execute": "qmp_capabilities"})

# 3. Screendump
resp = send_qmp({"execute": "screendump", "arguments": {"filename": ppm_path}})
print("Screendump response:", resp.strip())
s.close()

if not os.path.exists(ppm_path):
    print(f"Error: PPM file {ppm_path} not created.")
    sys.exit(1)

# 4. Parse PPM
with open(ppm_path, "rb") as f:
    header = f.readline().strip()
    if header != b"P6":
        print(f"Unknown PPM header: {header}")
        sys.exit(1)
    
    # Read past comments
    line = f.readline().strip()
    while line.startswith(b"#"):
        line = f.readline().strip()
    
    parts = line.split()
    if len(parts) == 2:
        width, height = int(parts[0]), int(parts[1])
        maxval = int(f.readline().strip())
    else:
        width = int(parts[0])
        height = int(parts[1])
        maxval = int(parts[2])
    
    data = f.read()

total_bytes = len(data)
non_zero = sum(1 for b in data if b != 0)
print(f"Screen size: {width}x{height}, total bytes: {total_bytes}, non-zero bytes: {non_zero}")

# Check colors
is_black = (non_zero == 0)
if is_black:
    print("SCREEN STATUS: ALL BLACK")
else:
    pct = (non_zero / total_bytes) * 100
    print(f"SCREEN STATUS: ACTIVE DISPLAY DETECTED ({pct:.2f}% non-black pixels)")

# 5. Convert PPM to PNG using pure Python zlib
def make_png(width, height, rgb_data, out_filename):
    raw = bytearray()
    row_bytes = width * 3
    for y in range(height):
        raw.append(0)  # filter type 0
        raw.extend(rgb_data[y * row_bytes : (y + 1) * row_bytes])
    
    compressed = zlib.compress(bytes(raw), 9)
    
    def png_chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(c) & 0xffffffff)
        return struct.pack(">I", len(data)) + c + crc

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    # IHDR: width, height, bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png.extend(png_chunk(b"IHDR", ihdr_data))
    png.extend(png_chunk(b"IDAT", compressed))
    png.extend(png_chunk(b"IEND", b""))

    with open(out_filename, "wb") as out_f:
        out_f.write(png)
    print(f"Saved PNG to {out_filename}")

make_png(width, height, data, png_path)

# Copy to Windows artifact dir if accessible
try:
    windows_path = "/mnt/c/Users/krant/.gemini/antigravity/brain/a1f377ff-ef8e-4e49-ba0c-3e0779e27801/qemu-screen.png"
    with open(png_path, "rb") as src, open(windows_path, "wb") as dst:
        dst.write(src.read())
    print(f"Copied PNG to {windows_path}")
except Exception as e:
    print("Could not copy to windows artifact path:", e)
