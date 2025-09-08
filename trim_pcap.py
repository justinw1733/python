#!/usr/bin/env python3
"""
PCAP Payload Trimmer

This script processes PCAP files to trim packet payloads based on a specific hex marker.
It finds the second occurrence of the marker '450001' and keeps only the data from that point onwards.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional, List

try:
    from scapy.all import rdpcap, wrpcap, Raw, PcapReader, PcapWriter
    from scapy.layers.inet import IP, TCP, UDP
except ImportError as e:
    print(f"Error: Required dependency 'scapy' not found. Install with: pip install scapy")
    sys.exit(1)


class PcapTrimmer:
    """PCAP file trimmer that removes payload data before the second occurrence of a marker."""
    
    def __init__(self, marker_hex: str = "450001"):
        """
        Initialize the PCAP trimmer.
        
        Args:
            marker_hex: Hexadecimal marker string to search for (default: "450001")
        """
        try:
            self.marker = bytes.fromhex(marker_hex)
        except ValueError:
            raise ValueError(f"Invalid hexadecimal marker: {marker_hex}")
        
        self.logger = logging.getLogger(__name__)
    
    def _process_packet(self, packet) -> bool:
        """
        Process a single packet to trim its payload.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            bool: True if packet was modified, False otherwise
        """
        try:
            raw_data = None
            is_raw_packet = False
            
            # Handle different packet types
            if hasattr(packet, '__class__') and packet.__class__.__name__ == 'Raw':
                # Packet is directly a Raw packet (due to unknown link layer)
                raw_data = bytes(packet)
                is_raw_packet = True
            else:
                # Check if packet contains a Raw layer
                try:
                    if Raw in packet:
                        raw_data = bytes(packet[Raw])
                        is_raw_packet = False
                    else:
                        # No raw data to process
                        return False
                except:
                    # If Raw check fails, packet doesn't have raw data
                    return False
            
            if not raw_data:
                return False
            
            first_index = raw_data.find(self.marker)
            
            if first_index == -1:
                return False
            
            second_index = raw_data.find(self.marker, first_index + len(self.marker))
            
            if second_index == -1:
                return False
            
            # Keep only data from the second marker onwards
            modified_data = raw_data[second_index:]
            
            # Update packet data based on packet type
            if is_raw_packet:
                # For Raw packets, replace the entire packet data
                packet.load = modified_data
            else:
                # For packets with Raw layer, update the Raw layer
                packet[Raw].load = modified_data
            
            # Clear checksums and lengths for recalculation (only if applicable)
            self._clear_checksums(packet)
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Error processing packet: {str(e)} (type: {type(e).__name__})")
            return False
    
    def _process_packet_copy(self, packet) -> bool:
        """
        Process a packet by creating a new modified copy instead of modifying in place.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            bool: True if packet was modified, False otherwise
        """
        try:
            raw_data = None
            is_raw_packet = False
            
            # Handle different packet types
            if hasattr(packet, '__class__') and packet.__class__.__name__ == 'Raw':
                # Packet is directly a Raw packet (due to unknown link layer)
                raw_data = bytes(packet)
                is_raw_packet = True
            else:
                # Check if packet contains a Raw layer
                try:
                    if Raw in packet:
                        raw_data = bytes(packet[Raw])
                        is_raw_packet = False
                    else:
                        # No raw data to process
                        return False
                except:
                    # If Raw check fails, packet doesn't have raw data
                    return False
            
            if not raw_data:
                return False
            
            first_index = raw_data.find(self.marker)
            
            if first_index == -1:
                return False
            
            second_index = raw_data.find(self.marker, first_index + len(self.marker))
            
            if second_index == -1:
                return False
            
            # Keep only data from the second marker onwards
            modified_data = raw_data[second_index:]
            
            # Create new packet with modified data
            if is_raw_packet:
                # For Raw packets, create a completely new Raw packet
                new_packet = Raw(load=modified_data)
                # Preserve linktype information if available
                if hasattr(packet, 'linktype'):
                    new_packet.linktype = packet.linktype
                # Replace the original packet's contents with the new one
                packet.__dict__.clear()
                packet.__dict__.update(new_packet.__dict__)
            else:
                # For packets with Raw layer, update the Raw layer
                packet[Raw].load = modified_data
                # Clear checksums for recalculation
                self._clear_checksums(packet)
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Error processing packet copy: {str(e)} (type: {type(e).__name__})")
            return False
    
    def _clear_checksums(self, packet) -> None:
        """
        Clear checksums and length fields to force recalculation.
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Only clear checksums for structured packets, not Raw packets
            if hasattr(packet, '__class__') and packet.__class__.__name__ == 'Raw':
                return
            
            # Safely check for and clear IP checksums
            try:
                if IP in packet:
                    if hasattr(packet[IP], 'len'):
                        del packet[IP].len
                    if hasattr(packet[IP], 'chksum'):
                        del packet[IP].chksum
            except:
                pass
            
            # Safely check for and clear TCP checksums
            try:
                if TCP in packet:
                    if hasattr(packet[TCP], 'chksum'):
                        del packet[TCP].chksum
            except:
                pass
            
            # Safely check for and clear UDP checksums
            try:
                if UDP in packet:
                    if hasattr(packet[UDP], 'len'):
                        del packet[UDP].len
                    if hasattr(packet[UDP], 'chksum'):
                        del packet[UDP].chksum
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Warning: Could not clear checksums: {e}")
    
    def trim_pcap_memory_efficient(self, input_path: str, output_path: str) -> dict:
        """
        Trim PCAP file using memory-efficient streaming approach.
        
        Args:
            input_path: Path to input PCAP file
            output_path: Path to output PCAP file
            
        Returns:
            dict: Statistics about the operation
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Create output directory if it doesn't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        stats = {
            'total_packets': 0,
            'modified_packets': 0,
            'raw_packets': 0,
            'input_size': input_file.stat().st_size,
            'output_size': 0
        }
        
        self.logger.info(f"Processing {input_path} -> {output_path}")
        self.logger.info("Note: Warnings about unknown LL types are normal for some PCAP formats")
        
        try:
            with PcapReader(str(input_file)) as reader:
                with PcapWriter(str(output_file)) as writer:
                    for packet in reader:
                        stats['total_packets'] += 1
                        
                        # Track Raw packets
                        if hasattr(packet, '__class__') and packet.__class__.__name__ == 'Raw':
                            stats['raw_packets'] += 1
                        
                        if self._process_packet(packet):
                            stats['modified_packets'] += 1
                        
                        writer.write(packet)
                        
                        # Progress logging for large files
                        if stats['total_packets'] % 10000 == 0:
                            self.logger.info(f"Processed {stats['total_packets']} packets")
            
            stats['output_size'] = output_file.stat().st_size
            
        except Exception as e:
            self.logger.error(f"Error processing PCAP file: {e}")
            # Clean up partial output file on error
            if output_file.exists():
                output_file.unlink()
            raise
        
        return stats
    
    def trim_pcap_batch(self, input_path: str, output_path: str, batch_size: int = 1000) -> dict:
        """
        Trim PCAP file using batch processing approach.
        
        Args:
            input_path: Path to input PCAP file
            output_path: Path to output PCAP file
            batch_size: Number of packets to process in each batch
            
        Returns:
            dict: Statistics about the operation
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Create output directory if it doesn't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        stats = {
            'total_packets': 0,
            'modified_packets': 0,
            'raw_packets': 0,
            'input_size': input_file.stat().st_size,
            'output_size': 0
        }
        
        self.logger.info(f"Processing {input_path} -> {output_path} (batch size: {batch_size})")
        self.logger.info("Note: Warnings about unknown LL types are normal for some PCAP formats")
        
        try:
            packets = rdpcap(str(input_file))
            stats['total_packets'] = len(packets)
            
            # Process packets in batches
            for i in range(0, len(packets), batch_size):
                batch = packets[i:i + batch_size]
                
                for packet in batch:
                    # Validate packet type
                    if not hasattr(packet, '__class__'):
                        self.logger.warning(f"Skipping invalid packet object: {type(packet)}")
                        continue
                        
                    # Track Raw packets
                    try:
                        if packet.__class__.__name__ == 'Raw':
                            stats['raw_packets'] += 1
                    except:
                        pass
                    
                    try:
                        # Try to process the packet
                        if self._process_packet_copy(packet):  # Use copy method
                            stats['modified_packets'] += 1
                    except Exception as proc_error:
                        self.logger.warning(f"Failed to process packet: {str(proc_error)}")
                        continue
                
                self.logger.info(f"Processed batch {i//batch_size + 1}/{(len(packets)-1)//batch_size + 1}")
            
            self.logger.info(f"Writing {len(packets)} packets to output file...")
            try:
                wrpcap(str(output_file), packets)
                self.logger.info("Successfully wrote output file")
            except Exception as write_error:
                self.logger.error(f"Error writing PCAP file: {str(write_error)} (type: {type(write_error).__name__})")
                raise
            stats['output_size'] = output_file.stat().st_size
            
        except Exception as e:
            self.logger.error(f"Error processing PCAP file: {str(e)} (type: {type(e).__name__})")
            # Clean up partial output file on error
            if output_file.exists():
                output_file.unlink()
            raise
        
        return stats
    
    def analyze_pcap(self, input_path: str, max_packets: int = 10) -> dict:
        """
        Analyze PCAP file structure for debugging purposes.
        
        Args:
            input_path: Path to input PCAP file
            max_packets: Maximum number of packets to analyze
            
        Returns:
            dict: Analysis results
        """
        input_file = Path(input_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        analysis = {
            'file_size': input_file.stat().st_size,
            'total_packets': 0,
            'packet_types': {},
            'raw_packets': 0,
            'samples': []
        }
        
        self.logger.info(f"Analyzing {input_path} (first {max_packets} packets)")
        
        try:
            with PcapReader(str(input_file)) as reader:
                for i, packet in enumerate(reader):
                    if i >= max_packets:
                        break
                    
                    analysis['total_packets'] += 1
                    packet_type = packet.__class__.__name__
                    analysis['packet_types'][packet_type] = analysis['packet_types'].get(packet_type, 0) + 1
                    
                    if packet_type == 'Raw':
                        analysis['raw_packets'] += 1
                    
                    # Store sample packet info
                    sample_info = {
                        'packet_num': i + 1,
                        'type': packet_type,
                        'length': len(packet),
                        'layers': []
                    }
                    
                    # Analyze packet layers
                    layer = packet
                    while layer:
                        sample_info['layers'].append(layer.__class__.__name__)
                        layer = layer.payload if hasattr(layer, 'payload') else None
                    
                    # Check if marker is present
                    has_marker = False
                    marker_count = 0
                    try:
                        if packet_type == 'Raw':
                            raw_data = bytes(packet)
                        else:
                            # Safely check if packet contains Raw layer
                            try:
                                if Raw in packet:
                                    raw_data = bytes(packet[Raw])
                                else:
                                    raw_data = b''
                            except:
                                raw_data = b''
                        
                        if raw_data:
                            marker_count = raw_data.count(self.marker)
                            has_marker = marker_count > 0
                    except:
                        pass
                    
                    sample_info['has_marker'] = has_marker
                    sample_info['marker_count'] = marker_count
                    
                    analysis['samples'].append(sample_info)
        
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file: {e}")
            raise
        
        return analysis


def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging configuration.
    
    Args:
        verbose: Enable verbose logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main() -> None:
    """
    Main function to handle command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Trim PCAP file payloads based on hex marker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.pcap output.pcap
  %(prog)s input.pcap output.pcap --marker 123456 --verbose
  %(prog)s input.pcap output.pcap --memory-efficient
  %(prog)s --analyze input.pcap --verbose
        """
    )
    
    parser.add_argument(
        "input_pcap",
        help="Path to input PCAP file"
    )
    
    parser.add_argument(
        "output_pcap",
        nargs='?',
        help="Path to output PCAP file (not required for --analyze)"
    )
    
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze PCAP structure instead of trimming"
    )
    
    parser.add_argument(
        "--marker",
        default="450001",
        help="Hexadecimal marker to search for (default: 450001)"
    )
    
    parser.add_argument(
        "--memory-efficient",
        action="store_true",
        help="Use memory-efficient streaming mode for large files"
    )
    
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for processing (default: 1000)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.analyze and not args.output_pcap:
        parser.error("output_pcap is required unless --analyze is used")
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        trimmer = PcapTrimmer(args.marker)
        
        if args.analyze:
            analysis = trimmer.analyze_pcap(args.input_pcap)
            
            logger.info("=== PCAP Analysis Results ===")
            logger.info(f"File size: {analysis['file_size']:,} bytes")
            logger.info(f"Packet types found: {analysis['packet_types']}")
            logger.info(f"Raw packets: {analysis['raw_packets']}")
            
            for sample in analysis['samples']:
                logger.info(f"Packet {sample['packet_num']}: {sample['type']} "
                          f"({sample['length']} bytes, layers: {sample['layers']}, "
                          f"marker: {sample['marker_count']} occurrences)")
        else:
            if args.memory_efficient:
                stats = trimmer.trim_pcap_memory_efficient(args.input_pcap, args.output_pcap)
            else:
                stats = trimmer.trim_pcap_batch(args.input_pcap, args.output_pcap, args.batch_size)
            
            logger.info("Processing completed successfully!")
            logger.info(f"Total packets: {stats['total_packets']}")
            logger.info(f"Modified packets: {stats['modified_packets']}")
            if 'raw_packets' in stats:
                logger.info(f"Raw packets (unknown LL type): {stats['raw_packets']}")
            logger.info(f"Input size: {stats['input_size']:,} bytes")
            logger.info(f"Output size: {stats['output_size']:,} bytes")
            
            if stats['input_size'] > 0:
                reduction = (1 - stats['output_size'] / stats['input_size']) * 100
                logger.info(f"Size reduction: {reduction:.1f}%")
        
    except Exception as e:
        logger.error(f"Error: {str(e)} (type: {type(e).__name__})")
        sys.exit(1)


if __name__ == "__main__":
    main()