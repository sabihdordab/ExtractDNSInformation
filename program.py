from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import IP

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

    
    return dns_types[qtype]


def analyze_pcap(file_path):
    """
    Analyzes a PCAP file for DNS packets and prints relevant information.

    Args:
    - file_path (str): Path to the PCAP file.

    Prints:
    - DNS Query - Source IP: {ip_src}, Destination IP: {ip_dst}, Domain: {query_name}, Type: {query_type}
    """
    packets = rdpcap(file_path)

    for p in packets:
        if p.haslayer(DNS) and p.haslayer(IP):
            ip_src = p[IP].src
            ip_dst = p[IP].dst
            dns_layer = p[DNS]

            # Check if it's a DNS Query (qr == 0) and has at least one question
            if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                # Decode the DNS query name from bytes to string
                query_name = dns_layer.qd.qname.decode('utf-8')
                query_type = dns_layer.qd.qtype
                query_type_str = dns_query_type(query_type)
                
                
                print(f'DNS Query - Source IP: {ip_src}, Destination IP: {ip_dst}, Domain: {query_name}, Type: {query_type_str}')

pcap_file = 'dnsfile.pcap'
analyze_pcap(pcap_file)
