from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
import socket
import os

def dns_query_type(qtype):
    """
    Converts DNS query type from integer to descriptive string.
    
    Args:
    - qtype (int): Integer representation of DNS query type.

    Returns:
    - str: Descriptive string of DNS query type.
    """
    
    dns_types = {
        1: "A",       # IPv4 address
        2: "NS",      # Name Server
        5: "CNAME",   # Canonical Name for an alias
        6: "SOA",     # Start Of a zone Authority
        12: "PTR",    # Domain name pointer
        15: "MX",     # Mail Exchange
        16: "TXT",    # Text strings
        28: "AAAA"    # IPv6 address
        # ...
    }

    
    if qtype in dns_types:
        return dns_types[qtype]
    else:
        return f"Unknown (Type {qtype})"


def analyze_pcap(file_path,output_file):
    """
    Analyzes a PCAP file for DNS packets and prints relevant information.

    Args:
    - file_path (str): Path to the PCAP file.
    - output_file (str): Path to the output file to write the results.

    Prints:
     - DNS Query - Source IP: {ip_src}, Destination IP (Target IP): {ip_dst}, Domain: {query_name}, Type: {query_type}, Resolved IP: {resolved_ip}
    """
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    with open(output_file, 'w') as f:
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                dns_layer = pkt[DNS]

                if dns_layer.qr == 0:
                    query_name = dns_layer.qd.qname.decode('utf-8')
                    query_type = dns_layer.qd.qtype
                    query_type_str = dns_query_type(query_type)
                    
                    try:
                        resolved_ip = socket.gethostbyname(query_name)
                    except:
                        resolved_ip = "N/A"
                    
                    dns_query_info = f'DNS Query - Source IP: {ip_src}, Destination IP: {ip_dst}, Domain: {query_name}, Type: {query_type_str}, Resolved IP: {resolved_ip}\n'
                    f.write(dns_query_info)
                
                    #print(f'DNS Query - Source IP: {ip_src}, Destination IP (Target IP): {ip_dst}, Domain: {query_name}, Type: {query_type_str}, Resolved IP: {resolved_ip}')
                    #print(pkt.show())
                    #print(pkt.summary())

file_path = input("Enter the path to the PCAP file: ")
output_file = input("Enter the path to the output file: ")

analyze_pcap(file_path, output_file)
