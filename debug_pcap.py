#!/usr/bin/env python3

import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, Raw
    from scapy.layers.inet import IP, TCP, UDP
except ImportError as e:
    print(f"Error: Required dependency 'scapy' not found. Install with: pip install scapy")
    sys.exit(1)

def debug_pcap(pcap_file):
    """Debug PCAP file to find the Raw packet issue."""
    print(f"Debugging: {pcap_file}")
    
    try:
        # Try to read the PCAP file
        packets = rdpcap(pcap_file)
        print(f"Successfully read {len(packets)} packets")
        
        for i, packet in enumerate(packets[:5]):  # Check first 5 packets
            print(f"\nPacket {i+1}:")
            print(f"  Type: {type(packet)}")
            print(f"  Class: {packet.__class__}")
            print(f"  Class name: {packet.__class__.__name__}")
            print(f"  Length: {len(packet)}")
            
            # Test Raw detection safely
            is_raw = packet.__class__.__name__ == 'Raw'
            print(f"  Is Raw packet: {is_raw}")
            
            if is_raw:
                try:
                    raw_data = bytes(packet)
                    print(f"  Raw data length: {len(raw_data)}")
                    print(f"  First 20 bytes: {raw_data[:20].hex()}")
                except Exception as e:
                    print(f"  Error getting raw data: {e}")
            else:
                try:
                    has_raw = Raw in packet
                    print(f"  Contains Raw layer: {has_raw}")
                    if has_raw:
                        raw_data = bytes(packet[Raw])
                        print(f"  Raw layer data length: {len(raw_data)}")
                except Exception as e:
                    print(f"  Error checking Raw layer: {e}")
            
            # Test marker search
            marker = bytes.fromhex('450001')
            try:
                if is_raw:
                    test_data = bytes(packet)
                else:
                    if Raw in packet:
                        test_data = bytes(packet[Raw])
                    else:
                        test_data = b''
                
                if test_data:
                    marker_count = test_data.count(marker)
                    print(f"  Marker '450001' occurrences: {marker_count}")
                else:
                    print(f"  No data to search for marker")
                    
            except Exception as e:
                print(f"  Error searching for marker: {e}")
                
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 debug_pcap.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    debug_pcap(pcap_file)