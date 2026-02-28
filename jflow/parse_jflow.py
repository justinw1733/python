#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Jflow/NetFlow Packet Parser

Parse Jflow (NetFlow) packets from PCAP files and analyze traffic statistics
for specific interfaces.

Features:
- Interactive mode for direction selection (input/output)
- Interactive mode for interface index input
- Statistics: Total Packets, Total Octets, Rate (bps)

Usage:
    python3 parse_jflow.py capture.pcap
    python3 parse_jflow.py capture.pcap -i 100 -d input
    python3 parse_jflow.py capture.pcap --interface 100 --direction output
"""

import argparse
import sys
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from scapy.all import rdpcap, UDP, IP
from scapy.utils import PcapReader

# NetFlow v5/v9 default port
NETFLOW_PORT = 2055


class NetFlowV5Record:
    """NetFlow v5 Flow Record."""
    
    def __init__(self, data: bytes):
        """
        Parse NetFlow v5 record (48 bytes).
        
        Format:
        - Source IP: 4 bytes
        - Destination IP: 4 bytes
        - Next hop: 4 bytes
        - Input interface: 2 bytes
        - Output interface: 2 bytes
        - Packets: 4 bytes
        - Octets: 4 bytes
        - First timestamp: 4 bytes
        - Last timestamp: 4 bytes
        - Source port: 2 bytes
        - Destination port: 2 bytes
        - Pad: 1 byte
        - TCP flags: 1 byte
        - Protocol: 1 byte
        - ToS: 1 byte
        - Source AS: 2 bytes
        - Destination AS: 2 bytes
        - Source mask: 1 byte
        - Destination mask: 1 byte
        - Pad: 2 bytes
        """
        if len(data) < 48:
            raise ValueError(f"Invalid NetFlow v5 record size: {len(data)}")
        
        # Parse record fields
        self.src_ip = self._parse_ip(data[0:4])
        self.dst_ip = self._parse_ip(data[4:8])
        self.next_hop = self._parse_ip(data[8:12])
        self.input_int = struct.unpack('!H', data[12:14])[0]
        self.output_int = struct.unpack('!H', data[14:16])[0]
        self.packets = struct.unpack('!I', data[16:20])[0]
        self.octets = struct.unpack('!I', data[20:24])[0]
        self.first = struct.unpack('!I', data[24:28])[0]
        self.last = struct.unpack('!I', data[28:32])[0]
        self.src_port = struct.unpack('!H', data[32:34])[0]
        self.dst_port = struct.unpack('!H', data[34:36])[0]
        self.tcp_flags = data[37]
        self.protocol = data[38]
        self.tos = data[39]
        self.src_as = struct.unpack('!H', data[40:42])[0]
        self.dst_as = struct.unpack('!H', data[42:44])[0]
        self.src_mask = data[44]
        self.dst_mask = data[45]
    
    @staticmethod
    def _parse_ip(data: bytes) -> str:
        """Convert 4-byte IP address to string."""
        return ".".join(str(b) for b in data)
    
    def __repr__(self):
        return (f"Flow({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}, "
                f"In:{self.input_int}, Out:{self.output_int}, "
                f"Pkts:{self.packets}, Octets:{self.octets})")


class NetFlowV5Packet:
    """NetFlow v5 Packet."""
    
    def __init__(self, data: bytes, timestamp: float):
        """
        Parse NetFlow v5 packet.
        
        Header format (24 bytes):
        - Version: 2 bytes (0x0005)
        - Count: 2 bytes (number of flow records)
        - Sys uptime: 4 bytes (ms)
        - Unix secs: 4 bytes
        - Unix nsecs: 4 bytes
        - Flow sequence: 4 bytes
        - Engine type: 1 byte
        - Engine ID: 1 byte
        - Sampling: 2 bytes
        """
        if len(data) < 24:
            raise ValueError(f"Invalid NetFlow v5 packet size: {len(data)}")
        
        self.timestamp = timestamp
        self.version = struct.unpack('!H', data[0:2])[0]
        self.count = struct.unpack('!H', data[2:4])[0]
        self.sys_uptime = struct.unpack('!I', data[4:8])[0]
        self.unix_secs = struct.unpack('!I', data[8:12])[0]
        self.unix_nsecs = struct.unpack('!I', data[12:16])[0]
        self.flow_sequence = struct.unpack('!I', data[16:20])[0]
        self.engine_type = data[20]
        self.engine_id = data[21]
        self.sampling = struct.unpack('!H', data[22:24])[0]
        
        # Parse flow records
        self.records = []
        offset = 24
        for i in range(self.count):
            if offset + 48 <= len(data):
                try:
                    record = NetFlowV5Record(data[offset:offset+48])
                    self.records.append(record)
                    offset += 48
                except Exception as e:
                    print(f"Warning: Failed to parse flow record {i}: {e}", file=sys.stderr)
                    break
            else:
                print(f"Warning: Incomplete flow record {i}, skipping", file=sys.stderr)
                break
    
    def __repr__(self):
        return f"NetFlowV5(Version:{self.version}, Count:{self.count}, Records:{len(self.records)})"


class JflowParser:
    """Parser for Jflow/NetFlow packets."""
    
    def __init__(self, port: int = NETFLOW_PORT, verbose: bool = False):
        """
        Initialize Jflow parser.
        
        Args:
            port: UDP port to filter for NetFlow packets
            verbose: Enable verbose logging
        """
        self.port = port
        self.verbose = verbose
        self.packets = []
        self.total_packet_count = 0
        self.netflow_packet_count = 0
        self.parse_error_count = 0
    
    def _parse_netflow_v9_template(self, data: bytes, offset: int):
        """
        Parse NetFlow v9 template flowset.
        
        Returns: dict of template_id -> list of field types
        """
        flowset_length = struct.unpack('!H', data[offset+2:offset+4])[0]
        template_offset = offset + 4
        end_offset = offset + flowset_length
        
        templates = {}
        
        while template_offset + 4 < end_offset:
            try:
                template_id = struct.unpack('!H', data[template_offset:template_offset+2])[0]
                field_count = struct.unpack('!H', data[template_offset+2:template_offset+4])[0]
                
                template_offset += 4
                fields = []
                
                for _ in range(field_count):
                    if template_offset + 4 > end_offset:
                        break
                    field_type = struct.unpack('!H', data[template_offset:template_offset+2])[0]
                    field_length = struct.unpack('!H', data[template_offset+2:template_offset+4])[0]
                    fields.append((field_type, field_length))
                    template_offset += 4
                
                templates[template_id] = fields
                self._log(f"Parsed template {template_id} with {len(fields)} fields")
            except:
                break
        
        return templates
    
    def _parse_netflow_v9_data(self, data: bytes, offset: int, template):
        """
        Parse NetFlow v9 data flowset using template.
        
        Returns: list of flow records
        """
        flowset_length = struct.unpack('!H', data[offset+2:offset+4])[0]
        data_offset = offset + 4
        end_offset = offset + flowset_length
        
        records = []
        
        # Calculate record length from template
        record_length = sum(field[1] for field in template)
        
        while data_offset + record_length <= end_offset:
            record = {
                'input_int': 0,
                'output_int': 0,
                'packets': 0,
                'octets': 0,
            }
            
            field_offset = data_offset
            for field_type, field_length in template:
                if field_offset + field_length > len(data):
                    break
                
                field_data = data[field_offset:field_offset+field_length]
                
                # NetFlow v9 field types (common ones)
                # 1 = IN_BYTES, 2 = IN_PKTS, 10 = INPUT_SNMP, 14 = OUTPUT_SNMP
                # 23 = OUT_BYTES, 24 = OUT_PKTS
                if field_type == 1:  # IN_BYTES
                    record['octets'] += self._parse_int(field_data)
                elif field_type == 2:  # IN_PKTS
                    record['packets'] += self._parse_int(field_data)
                elif field_type == 23:  # OUT_BYTES  
                    record['octets'] += self._parse_int(field_data)
                elif field_type == 24:  # OUT_PKTS
                    record['packets'] += self._parse_int(field_data)
                elif field_type == 10:  # INPUT_SNMP (input interface)
                    record['input_int'] = self._parse_int(field_data)
                elif field_type == 14:  # OUTPUT_SNMP (output interface)
                    record['output_int'] = self._parse_int(field_data)
                
                field_offset += field_length
            
            # Create record object
            class NetFlowV9Record:
                def __init__(self, data):
                    self.input_int = data['input_int']
                    self.output_int = data['output_int']
                    self.packets = data['packets']
                    self.octets = data['octets']
            
            records.append(NetFlowV9Record(record))
            data_offset = field_offset
        
        return records
    
    def _parse_int(self, data: bytes) -> int:
        """Parse integer from bytes of varying length."""
        if len(data) == 1:
            return struct.unpack('!B', data)[0]
        elif len(data) == 2:
            return struct.unpack('!H', data)[0]
        elif len(data) == 4:
            return struct.unpack('!I', data)[0]
        elif len(data) == 8:
            return struct.unpack('!Q', data)[0]
        else:
            # For other sizes, convert bytes to int
            return int.from_bytes(data, byteorder='big')
    
    def _parse_netflow_v9(self, data: bytes, timestamp: float):
        """
        NetFlow v9 parser with template support.
        
        NetFlow v9 is template-based - templates define the structure of data records.
        """
        if len(data) < 20:
            return None
        
        version = struct.unpack('!H', data[0:2])[0]
        count = struct.unpack('!H', data[2:4])[0]
        sys_uptime = struct.unpack('!I', data[4:8])[0]
        unix_secs = struct.unpack('!I', data[8:12])[0]
        sequence = struct.unpack('!I', data[12:16])[0]
        source_id = struct.unpack('!I', data[16:20])[0]
        
        # Create packet structure
        class NetFlowV9Packet:
            def __init__(self):
                self.timestamp = timestamp
                self.version = version
                self.count = count
                self.sys_uptime = sys_uptime
                self.unix_secs = unix_secs
                self.source_id = source_id
                self.records = []
            
            def __repr__(self):
                return f"NetFlowV9(Version:{self.version}, Count:{self.count}, Records:{len(self.records)})"
        
        nf_packet = NetFlowV9Packet()
        
        # Initialize template cache if not exists
        if not hasattr(self, '_v9_templates'):
            self._v9_templates = {}
        
        # Parse flowsets
        offset = 20
        while offset + 4 <= len(data):
            flowset_id = struct.unpack('!H', data[offset:offset+2])[0]
            flowset_length = struct.unpack('!H', data[offset+2:offset+4])[0]
            
            if flowset_length < 4 or offset + flowset_length > len(data):
                break
            
            # FlowSet ID 0 = Template FlowSet
            if flowset_id == 0:
                templates = self._parse_netflow_v9_template(data, offset)
                self._v9_templates.update(templates)
            
            # FlowSet ID >= 256 = Data FlowSet
            elif flowset_id >= 256:
                # Use cached template to parse data
                if flowset_id in self._v9_templates:
                    template = self._v9_templates[flowset_id]
                    records = self._parse_netflow_v9_data(data, offset, template)
                    nf_packet.records.extend(records)
                else:
                    self._log(f"No template found for flowset ID {flowset_id}")
            
            offset += flowset_length
        
        self._log(f"Parsed NetFlow v9 packet with {len(nf_packet.records)} records")
        return nf_packet
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[DEBUG] {message}", file=sys.stderr)
    
    def parse_pcap(self, pcap_file: str) -> List[NetFlowV5Packet]:
        """
        Parse PCAP file and extract NetFlow packets.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            List of parsed NetFlow packets
        """
        self._log(f"Opening PCAP file: {pcap_file}")
        
        udp_port_match_count = 0
        version_mismatch_count = 0
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    self.total_packet_count += 1
                    
                    # Check if packet has UDP layer
                    if not packet.haslayer(UDP):
                        continue
                    
                    udp_layer = packet[UDP]
                    
                    # Filter by NetFlow port
                    if udp_layer.dport != self.port and udp_layer.sport != self.port:
                        continue
                    
                    udp_port_match_count += 1
                    
                    # Get UDP payload
                    payload = bytes(udp_layer.payload)
                    if len(payload) < 24:
                        self._log(f"UDP payload too small: {len(payload)} bytes (need at least 24)")
                        continue
                    
                    # Check NetFlow version
                    version = struct.unpack('!H', payload[0:2])[0]
                    
                    # Show first few bytes for debugging
                    self._log(f"Found UDP packet on port {self.port}, version field: {version} (0x{version:04x}), "
                             f"first 16 bytes: {payload[:16].hex()}")
                    
                    if version == 5:
                        # NetFlow v5
                        timestamp = float(packet.time)
                        try:
                            nf_packet = NetFlowV5Packet(payload, timestamp)
                            self.packets.append(nf_packet)
                            self.netflow_packet_count += 1
                            self._log(f"Parsed NetFlow v5 packet with {len(nf_packet.records)} records")
                        except Exception as e:
                            self.parse_error_count += 1
                            self._log(f"Error parsing NetFlow v5 packet: {e}")
                    elif version == 9:
                        # NetFlow v9 - add basic support
                        self._log(f"Found NetFlow v9 packet (not fully supported yet)")
                        version_mismatch_count += 1
                        # Try to parse as v9 for statistics
                        try:
                            timestamp = float(packet.time)
                            nf_packet = self._parse_netflow_v9(payload, timestamp)
                            if nf_packet:
                                self.packets.append(nf_packet)
                                self.netflow_packet_count += 1
                        except Exception as e:
                            self._log(f"Error parsing NetFlow v9 packet: {e}")
                    elif version == 10:
                        # IPFIX (NetFlow v10)
                        self._log(f"Found IPFIX/NetFlow v10 packet (not supported)")
                        version_mismatch_count += 1
                    else:
                        self._log(f"Unknown NetFlow version {version} (0x{version:04x})")
                        version_mismatch_count += 1
        
        except FileNotFoundError:
            print(f"Error: File not found: {pcap_file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading PCAP file: {e}", file=sys.stderr)
            sys.exit(1)
        
        self._log(f"Processed {self.total_packet_count} packets, "
                 f"found {self.netflow_packet_count} NetFlow packets")
        
        # Print diagnostic info if no packets found
        if self.netflow_packet_count == 0 and udp_port_match_count > 0:
            print(f"\nDiagnostic Info:", file=sys.stderr)
            print(f"  UDP packets on port {self.port}: {udp_port_match_count}", file=sys.stderr)
            print(f"  Version mismatches: {version_mismatch_count}", file=sys.stderr)
            print(f"  Hint: Run with --verbose to see detailed packet analysis", file=sys.stderr)
        
        return self.packets
    
    def analyze_interface(self, interface_index: int, direction: str) -> Dict:
        """
        Analyze traffic statistics for a specific interface.
        
        Args:
            interface_index: Interface index to analyze
            direction: 'input' or 'output'
            
        Returns:
            Dictionary with statistics
        """
        total_packets = 0
        total_octets = 0
        first_timestamp = None
        last_timestamp = None
        flow_count = 0
        
        for nf_packet in self.packets:
            for record in nf_packet.records:
                # Match interface based on direction
                # Use getattr to handle both v5 and v9 records
                input_int = getattr(record, 'input_int', 0)
                output_int = getattr(record, 'output_int', 0)
                packets = getattr(record, 'packets', 0)
                octets = getattr(record, 'octets', 0)
                
                if direction == 'input' and input_int == interface_index:
                    total_packets += packets
                    total_octets += octets
                    flow_count += 1
                    
                    # Track timestamps
                    if first_timestamp is None or nf_packet.timestamp < first_timestamp:
                        first_timestamp = nf_packet.timestamp
                    if last_timestamp is None or nf_packet.timestamp > last_timestamp:
                        last_timestamp = nf_packet.timestamp
                
                elif direction == 'output' and output_int == interface_index:
                    total_packets += packets
                    total_octets += octets
                    flow_count += 1
                    
                    # Track timestamps
                    if first_timestamp is None or nf_packet.timestamp < first_timestamp:
                        first_timestamp = nf_packet.timestamp
                    if last_timestamp is None or nf_packet.timestamp > last_timestamp:
                        last_timestamp = nf_packet.timestamp
        
        # Calculate rate (bps)
        duration = 0
        rate_bps = 0
        if first_timestamp and last_timestamp and last_timestamp > first_timestamp:
            duration = last_timestamp - first_timestamp
            rate_bps = (total_octets * 8) / duration  # Convert bytes to bits
        
        return {
            'interface_index': interface_index,
            'direction': direction,
            'total_packets': total_packets,
            'total_octets': total_octets,
            'flow_count': flow_count,
            'duration': duration,
            'rate_bps': rate_bps,
            'first_timestamp': first_timestamp,
            'last_timestamp': last_timestamp
        }


def format_bps(bps: float) -> str:
    """Format bits per second in human-readable format."""
    if bps >= 1_000_000_000:
        return f"{bps/1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps/1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps/1_000:.2f} Kbps"
    else:
        return f"{bps:.2f} bps"


def print_statistics(stats: Dict):
    """Print interface statistics."""
    print("\n" + "="*60)
    print("Jflow Interface Analysis")
    print("="*60)
    print(f"Interface Index: {stats['interface_index']} ({stats['direction']})")
    print(f"Total Flows:     {stats['flow_count']}")
    print(f"Total Packets:   {stats['total_packets']:,}")
    print(f"Total Octets:    {stats['total_octets']:,} bytes")
    
    if stats['duration'] > 0:
        print(f"Duration:        {stats['duration']:.2f} seconds")
        print(f"Rate (bps):      {stats['rate_bps']:,.2f} bps ({format_bps(stats['rate_bps'])})")
    else:
        print(f"Rate (bps):      N/A (insufficient time data)")
    
    print("="*60 + "\n")


def get_interactive_input(parser: 'JflowParser') -> Tuple[str, int]:
    """
    Get direction and interface index from user interactively.
    
    Args:
        parser: JflowParser instance to get available interfaces
    
    Returns:
        Tuple of (direction, interface_index)
    """
    # Collect available interfaces
    input_ints = set()
    output_ints = set()
    
    for pkt in parser.packets:
        for rec in pkt.records:
            input_int = getattr(rec, 'input_int', 0)
            output_int = getattr(rec, 'output_int', 0)
            if input_int > 0:
                input_ints.add(input_int)
            if output_int > 0:
                output_ints.add(output_int)
    
    # Get direction
    print("\nSelect direction:")
    print("  1. input")
    print("  2. output (default)")
    
    while True:
        direction_input = input("Enter choice [1-2] (default: 2): ").strip()
        
        # Default to output
        if direction_input == '' or direction_input == '2':
            direction = 'output'
            break
        elif direction_input == '1':
            direction = 'input'
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")
    
    # Show available interfaces based on direction
    available_ints = sorted(input_ints if direction == 'input' else output_ints)
    
    if not available_ints:
        print(f"\nNo {direction} interfaces found in this capture file.")
        sys.exit(1)
    
    print(f"\nAvailable {direction} interfaces in this capture:")
    for idx, intf in enumerate(available_ints, 1):
        print(f"  {idx}. Interface {intf}")
    
    # Get interface index
    while True:
        try:
            interface_str = input(f"\nEnter interface number [1-{len(available_ints)}] or interface index: ").strip()
            
            if not interface_str:
                print("Please enter a value.")
                continue
            
            interface_num = int(interface_str)
            
            # Check if it's a list number (1-based)
            if 1 <= interface_num <= len(available_ints):
                interface_index = available_ints[interface_num - 1]
                break
            # Check if it's a valid interface index
            elif interface_num in available_ints:
                interface_index = interface_num
                break
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(available_ints)}, or a valid interface index.")
        except ValueError:
            print("Invalid input. Please enter a numeric value.")
    
    return direction, interface_index


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Parse Jflow/NetFlow packets from PCAP files and analyze interface statistics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  %(prog)s capture.pcap
  
  # Non-interactive mode
  %(prog)s capture.pcap -i 100 -d input
  %(prog)s capture.pcap --interface 100 --direction output
  
  # With custom NetFlow port
  %(prog)s capture.pcap -p 9995 -i 100 -d input
        """
    )
    
    parser.add_argument("pcap_file",
                       help="Input PCAP file path")
    
    parser.add_argument("-i", "--interface",
                       type=int,
                       help="Interface index to analyze")
    
    parser.add_argument("-d", "--direction",
                       choices=['input', 'output'],
                       help="Direction: input or output")
    
    parser.add_argument("-p", "--port",
                       type=int,
                       default=NETFLOW_PORT,
                       help=f"UDP port for NetFlow traffic (default: {NETFLOW_PORT})")
    
    parser.add_argument("-v", "--verbose",
                       action="store_true",
                       help="Enable verbose debug output")
    
    args = parser.parse_args()
    
    # Validate arguments
    if (args.interface is not None) != (args.direction is not None):
        parser.error("Both --interface and --direction must be specified together, "
                    "or neither (for interactive mode)")
    
    # Create parser
    jflow_parser = JflowParser(port=args.port, verbose=args.verbose)
    
    # Parse PCAP file
    print(f"Parsing Jflow/NetFlow packets from: {args.pcap_file}")
    packets = jflow_parser.parse_pcap(args.pcap_file)
    
    if not packets:
        print("No NetFlow packets found in the PCAP file.", file=sys.stderr)
        print(f"Hint: Ensure NetFlow packets are on UDP port {args.port}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(packets)} NetFlow packets")
    
    # Get parameters (interactive or from arguments)
    if args.interface is not None and args.direction is not None:
        direction = args.direction
        interface_index = args.interface
    else:
        direction, interface_index = get_interactive_input(jflow_parser)
    
    # Analyze interface
    stats = jflow_parser.analyze_interface(interface_index, direction)
    
    if stats['flow_count'] == 0:
        print(f"\nNo flows found for interface {interface_index} ({direction})", file=sys.stderr)
        sys.exit(1)
    
    # Print results
    print_statistics(stats)


if __name__ == "__main__":
    main()
