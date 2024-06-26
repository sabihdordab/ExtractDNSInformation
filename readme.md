# DNS Packet Analyzer

This Python script analyzes a PCAP file to extract DNS query information and writes the results to an output file.

## Dependencies
- [Scapy](https://scapy.readthedocs.io/en/latest/): Used for reading PCAP files and analyzing packets.

## Usage
1. **Installation**:
   - Ensure you have Python installed.
   - Install Scapy using pip if not already installed:
     ```
     pip install scapy
     ```

2. **Running the Script**:
   - Clone or download the script to your local machine.
   - Open a terminal or command prompt.
   - Navigate to the directory containing the script:

     ```
     cd /path/to/script/directory
     ```

   - Run the script:

     ```
     python dns_analyzer.py
     ```

   - Follow the prompts:
     - Enter the path to the PCAP file (`file_path`).
     - Enter the path where you want to save the output file (`output_file`).

3. **Output**:
   - The script will generate an output file (`dns_analysis_results.txt`) containing details of DNS queries found in the PCAP file. Each DNS query is listed in the format:

     ```
     DNS Query - Source IP: <source_ip>, Destination IP: <destination_ip>, Domain: <domain_name>, Type: <query_type>, Resolved IP: <resolved_ip>
     ```


