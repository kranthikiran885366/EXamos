import socket
import threading

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def proxy_port(listen_ip, listen_port, target_ip, target_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_ip, listen_port))
    server.listen(128)
    print(f"[VMware Relay] Forwarding {listen_ip}:{listen_port} -> {target_ip}:{target_port}", flush=True)

    while True:
        try:
            client, _ = server.accept()
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.connect((target_ip, target_port))
            threading.Thread(target=forward, args=(client, target), daemon=True).start()
            threading.Thread(target=forward, args=(target, client), daemon=True).start()
        except Exception:
            continue

if __name__ == "__main__":
    proxy_port("192.168.19.1", 8895, "127.0.0.1", 8895)
