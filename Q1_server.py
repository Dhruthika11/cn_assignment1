# server.py
import socket
import json
from scapy.all import DNS
import struct # Import the struct library

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 65000
RULES_FILE = 'rules.json'
# (Your IP_POOL, load_rules, and get_rule_for_time functions remain the same)
IP_POOL = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"]

def load_rules(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Rules file '{filename}' not found.")
        return None

def get_rule_for_time(hour, rules):
    for rule in rules["timestamp_rules"]["time_based_routing"].values():
        start_hour, end_hour = [int(t.split(':')[0]) for t in rule["time_range"].split('-')]
        if start_hour > end_hour:
            if hour >= start_hour or hour <= end_hour:
                return rule
        else:
            if start_hour <= hour <= end_hour:
                return rule
    return None

# --- CHANGE START ---
# Helper function to reliably receive a message of a specific length
def recv_all(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def recv_msg(sock):
    # First, read the 4-byte length prefix
    raw_msglen = recv_all(sock, 4)
    if not raw_msglen:
        return None
    # Unpack it to get the integer length
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Now, read exactly that many bytes to get the full message
    return recv_all(sock, msglen)
# --- CHANGE END ---

def start_server():
    rules = load_rules(RULES_FILE)
    if not rules:
        return
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    # --- CHANGE START ---
                    # Use our new reliable function to get one complete message
                    data = recv_msg(conn)
                    # --- CHANGE END ---

                    if not data:
                        print("   - Client disconnected.")
                        break
                    
                    try:
                        custom_header = data[:8].decode('utf-8')
                        hour = int(custom_header[:2])
                        seq_id = int(custom_header[-2:])
                        
                        rule = get_rule_for_time(hour, rules)
                        
                        if rule:
                            start_index = rule['ip_pool_start']
                            offset = seq_id % rule['hash_mod']
                            final_index = start_index + offset
                            resolved_ip = IP_POOL[final_index]
                            
                            print(f"   - Header: {custom_header} -> Resolved IP: {resolved_ip}")
                            conn.sendall(resolved_ip.encode('utf-8'))
                        else:
                            print(f"   - Header: {custom_header} -> No matching rule found.")
                            conn.sendall(b"Error: No matching rule")
                    
                    except (ValueError, IndexError, UnicodeDecodeError) as e:
                        print(f" [ERROR] Could not process packet. Details: {e}. Skipping.")
                        # You might still want a fallback here, or just skip responding
                        conn.sendall(b"Error: Server failed to process packet")

if __name__ == "__main__":
    start_server()