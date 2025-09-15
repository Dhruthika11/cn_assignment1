# client.py
import socket
import datetime
import pytz
import pandas as pd
from scapy.all import rdpcap, DNS, DNSQR
import struct # Import the struct library

# --- Configuration ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65000
PCAP_FILE = '9.pcap' # Use '9.pcap' or your chosen file
TIMEZONE = "Asia/Kolkata"

def build_custom_header(seq_id, tz):
    """Generates a custom header in HHMMSSID format."""
    now = datetime.datetime.now(tz)
    return f"{now.strftime('%H%M%S')}{seq_id:02d}"

def run_client():
    """Reads a PCAP, sends queries to the server, and generates a report."""
    packets = rdpcap(PCAP_FILE)
    report_data = []
    seq_id = 0
    tz = pytz.timezone(TIMEZONE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
        except ConnectionRefusedError:
            print(f"Error: Connection refused. Is 'server.py' running?")
            return

        dns_query_packets = [p for p in packets if p.haslayer(DNS) and p[DNS].qr == 0]

        if not dns_query_packets:
            print(f"Warning: No DNS queries found in '{PCAP_FILE}'.")
            return

        for pkt in dns_query_packets:
            domain = pkt[DNSQR].qname.decode().strip(".")
            header = build_custom_header(seq_id, tz)
            
            message_to_send = header.encode('utf-8') + bytes(pkt[DNS])
            
            # --- CHANGE START ---
            # 1. Get the length of the message
            msg_len = len(message_to_send)
            # 2. Pack the length into 4 bytes and send it first
            client_socket.sendall(struct.pack('>I', msg_len))
            # 3. Now send the actual message
            client_socket.sendall(message_to_send)
            # --- CHANGE END ---
            
            try:
                response_ip = client_socket.recv(1024).decode('utf-8')
                report_data.append((header, domain, response_ip))
                print(f"Client Log: Header {header} -> Got IP: {response_ip}") # Added for clarity
            except ConnectionAbortedError:
                print("Error: Connection was aborted by the server.")
                break
            
            seq_id += 1
    
    if report_data:
        df_report = pd.DataFrame(report_data, columns=["Custom Header", "Queried Domain", "Resolved IP Address"])
        print("\n--- Final DNS Resolution Report ---")
        print(df_report)
        df_report.to_csv('dns_report.csv', index=False)
        print("\nReport successfully saved to 'dns_report.csv'")

if __name__ == "__main__":
    run_client()