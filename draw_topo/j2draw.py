#!/usr/bin/env python3
"""
Network Topology Drawing Tool
Generates network topology diagrams from Junos configuration files and LLDP data
"""

import argparse
import os
import sys
import json
import re
import xml.etree.ElementTree as ET
import math
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
import traceback


def create_argument_parser():
    """Create and configure argument parser"""
    usage_text = """
USAGE:
    python j2draw.py [options]

NOTE:
    Default output format is now .drawio (diagrams.net format) instead of .png
    for better network topology diagram editing and sharing capabilities.
"""
    
    parser = argparse.ArgumentParser(
        description="Network Topology Drawing Tool" + usage_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    # Help option
    parser.add_argument(
        "-h", "--help",
        action="help",
        help="Show this help message and exit"
    )
    
    # IPv4 option
    parser.add_argument(
        "-4", "--ipv4",
        action="store_true",
        help="Display IPv4 information including interface IPs and connection details"
    )
    
    # Layer 2 option
    parser.add_argument(
        "-l2", "--layer2",
        action="store_true",
        help="Display Layer 2 information including trunk and access interface VLAN details"
    )
    
    return parser


def list_subdirectories_with_custom_first():
    """List subdirectories with 'custom' directory first, numbered"""
    current_dir = Path(".")
    # Filter out hidden directories (those starting with a dot) and common cache directories
    hidden_and_cache_dirs = {'.', '..', '__pycache__'}
    subdirs = [d for d in current_dir.iterdir() 
               if d.is_dir() and not d.name.startswith('.') and d.name not in hidden_and_cache_dirs]
    
    # Separate 'custom' directory if it exists
    custom_dir = None
    other_dirs = []
    
    for d in subdirs:
        if d.name == "custom":
            custom_dir = d
        else:
            other_dirs.append(d)
    
    # Sort other directories alphabetically
    other_dirs.sort(key=lambda x: x.name)
    
    # Combine with custom first
    if custom_dir:
        all_dirs = [custom_dir] + other_dirs
    else:
        all_dirs = other_dirs
    
    return all_dirs


def select_directory():
    """Prompt user to select a directory for topology creation"""
    print("Select a directory for topology creation:")
    
    dirs = list_subdirectories_with_custom_first()
    
    # Display directories with numbers
    for i, d in enumerate(dirs, 1):
        marker = " (default)" if d.name == "custom" else ""
        print(f"{i}. {d.name}{marker}")
    
    # Add option to create new directory
    print(f"{len(dirs) + 1}. Create a new directory")
    
    while True:
        try:
            choice = input(f"\nEnter your choice (1-{len(dirs) + 1}) [default: 1]: ").strip()
            
            if not choice:
                # Default to custom directory (first option) if exists, otherwise first directory
                selected_dir = dirs[0] if dirs else None
                if selected_dir:
                    return selected_dir
                else:
                    print("No directories found. Please create a new directory.")
                    choice = str(len(dirs) + 1)
            
            choice_num = int(choice)
            
            if 1 <= choice_num <= len(dirs):
                return dirs[choice_num - 1]
            elif choice_num == len(dirs) + 1:
                # Create new directory
                return create_new_directory()
            else:
                print(f"Please enter a number between 1 and {len(dirs) + 1}")
        except ValueError:
            print("Please enter a valid number")


def create_new_directory():
    """Prompt user to create a new directory"""
    while True:
        dir_name = input("Enter the name for the new directory: ").strip()
        if dir_name:
            break
        print("Directory name cannot be empty.")
    
    new_dir = Path(dir_name)
    try:
        new_dir.mkdir(exist_ok=True)
        (new_dir / "config").mkdir(exist_ok=True)
        (new_dir / "lldp").mkdir(exist_ok=True)
        print(f"\nCreated directory '{dir_name}' with 'config' and 'lldp' subdirectories.")
        print(f"\nPlease place:")
        print(f"  - Device configuration files in '{dir_name}/config/'")
        print(f"  - LLDP neighbor detail JSON files in '{dir_name}/lldp/'")
        print(f"\nThen run the program again to generate the topology.")
        sys.exit(0)
    except Exception as e:
        print(f"Error creating directory: {e}")
        sys.exit(1)


def validate_required_files(selected_dir: Path):
    """Validate that required files exist in config and lldp directories"""
    config_dir = selected_dir / "config"
    lldp_dir = selected_dir / "lldp"
    
    if not config_dir.exists():
        print(f"Error: Configuration directory '{config_dir}' does not exist")
        return False
        
    if not lldp_dir.exists():
        print(f"Error: LLDP directory '{lldp_dir}' does not exist")
        return False
    
    # Check if there are any files in the directories
    config_files = list(config_dir.glob("*.txt"))
    lldp_files = list(lldp_dir.glob("*.txt"))
    
    if not config_files:
        print(f"Error: No configuration files found in '{config_dir}'")
        return False
        
    if not lldp_files:
        print(f"Error: No LLDP files found in '{lldp_dir}'")
        return False
    
    return True


class SpatialIndex:
    """Simple spatial index for collision detection using grid-based approach"""
    
    def __init__(self, width: int, height: int, cell_size: int = 64):
        self.width = width
        self.height = height
        self.cell_size = cell_size
        self.grid_width = (width + cell_size - 1) // cell_size
        self.grid_height = (height + cell_size - 1) // cell_size
        self.grid = defaultdict(list)  # grid[cell_key] = [bbox_list]
    
    def _get_cell_key(self, x: int, y: int) -> tuple:
        """Convert world coordinates to grid cell key"""
        grid_x = max(0, min(self.grid_width - 1, x // self.cell_size))
        grid_y = max(0, min(self.grid_height - 1, y // self.cell_size))
        return (grid_x, grid_y)
    
    def insert(self, bbox: dict, key: str):
        """Insert bounding box into spatial index"""
        # Get all cells this bbox overlaps
        min_cell = self._get_cell_key(bbox['x'], bbox['y'])
        max_cell = self._get_cell_key(bbox['x'] + bbox['w'], bbox['y'] + bbox['h'])
        
        for gx in range(min_cell[0], max_cell[0] + 1):
            for gy in range(min_cell[1], max_cell[1] + 1):
                self.grid[(gx, gy)].append({'bbox': bbox, 'key': key})
    
    def overlaps(self, bbox: dict) -> bool:
        """Check if bbox overlaps with any existing bbox in index"""
        min_cell = self._get_cell_key(bbox['x'], bbox['y'])
        max_cell = self._get_cell_key(bbox['x'] + bbox['w'], bbox['y'] + bbox['h'])
        
        for gx in range(min_cell[0], max_cell[0] + 1):
            for gy in range(min_cell[1], max_cell[1] + 1):
                for item in self.grid.get((gx, gy), []):
                    if self._bbox_intersects(bbox, item['bbox']):
                        return True
        return False
    
    def _bbox_intersects(self, bbox1: dict, bbox2: dict) -> bool:
        """Check if two bounding boxes intersect"""
        return not (bbox1['x'] + bbox1['w'] <= bbox2['x'] or
                   bbox2['x'] + bbox2['w'] <= bbox1['x'] or
                   bbox1['y'] + bbox1['h'] <= bbox2['y'] or
                   bbox2['y'] + bbox2['h'] <= bbox1['y'])


class LabelEndpoint:
    """Represents a label endpoint for placement"""
    
    def __init__(self, device_name: str, interface: str, device_center: tuple, connection_angle: float, priority: int = 0):
        self.device_name = device_name
        self.interface = interface
        self.device_center = device_center  # (x, y)
        self.connection_angle = connection_angle  # angle to other device in radians
        self.priority = priority
        self.text = interface
    
    def __lt__(self, other):
        return self.priority < other.priority
class DeviceInfo:
    """Device information container"""
    def __init__(self, name: str):
        self.name = name
        self.display_name = name
        self.device_type = 'unknown'  # 'router', 'switch', or 'unknown'
        self.router_id = ""  # Store router ID for display
        self.interfaces = {}  # interface_name: ip_address_info
        self.neighbors = []  # List of (local_port, remote_device, remote_port)
        self.interface_ae = {}  # physical_interface: ae_interface mapping
        self.trunk_interfaces = {}  # trunk_interface: vlan_members_list
        self.vlan_irb_mapping = {}  # vlan_name: (irb_unit, vlan_id)
        self.position: Tuple[int, int] = (0, 0)  # x, y coordinates for device placement


class TopologyBuilder:
    """Build network topology from configuration and LLDP data"""
    
    def __init__(self, config_dir: str, lldp_dir: str):
        self.config_dir = Path(config_dir)
        self.lldp_dir = Path(lldp_dir)
        self.devices: Dict[str, DeviceInfo] = {}
        self.connections: Set[Tuple[str, str, str, str]] = set()  # (dev1, port1, dev2, port2)
    
    def extract_hostname_from_filename(self, filename: str) -> str:
        """Extract hostname from config filename"""
        # Remove file extensions and suffixes like -config
        name = filename.replace('.txt', '')
        name = re.sub(r'-config$', '', name)  # Remove -config suffix but preserve -s-ng
        name = re.sub(r'-json-detail-lldp$', '', name)  # Handle detailed LLDP files
        name = re.sub(r'-json-lldp$', '', name)  # Handle simple LLDP files
        name = re.sub(r'-lldp$', '', name)  # Handle LLDP files
        # Remove _re suffix if present (common in Juniper LLDP data)
        name = re.sub(r'_re$', '', name)
        return name
    
    def parse_config_file(self, config_file: Path) -> DeviceInfo:
        """Parse Junos configuration file"""
        hostname = self.extract_hostname_from_filename(config_file.name)
        # Config files are named like 'vqfx1-config.txt', hostname should be 'vqfx1'
        # Use the actual hostname without adding -s-ng suffix
        device = DeviceInfo(hostname)
        device.display_name = hostname  # Store clean name for display
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Determine device type based on configuration patterns first (more reliable)
            # Check name patterns first to properly classify vqfx as switches
            if re.match(r'.*mx.*', hostname, re.IGNORECASE) or re.match(r'.*ptx.*', hostname, re.IGNORECASE) or re.match(r'.*vmx.*', hostname, re.IGNORECASE):
                device.device_type = 'router'
            elif re.match(r'.*qfx.*', hostname, re.IGNORECASE) or re.match(r'.*ex.*', hostname, re.IGNORECASE):
                device.device_type = 'switch'
            else:
                # Fallback to configuration-based detection
                if re.search(r'routing-options|protocols bgp', content):
                    device.device_type = 'router'
                elif re.search(r'ethernet-switching', content):
                    device.device_type = 'switch'
                else:
                    device.device_type = 'unknown'
            
            # Extract router-id information
            # Handle both set format and hierarchical format
            router_id_match = re.search(r'set routing-options router-id (\S+)', content)
            if not router_id_match:
                # Try hierarchical format - look for router-id at the same level as routing-options
                router_id_match = re.search(r'routing-options\s*{.*?router-id\s+(\S+);', content, re.DOTALL)
            
            if router_id_match:
                device.router_id = router_id_match.group(1)
            
            # Extract AE interface mappings
            # Look for patterns like "ether-options { 802.3ad ae0; }" in hierarchical format
            ae_interface_matches = re.findall(r'(\S+)\s+{[^}]*802\.3ad\s+(\S+);', content, re.DOTALL)
            for physical_interface, ae_interface in ae_interface_matches:
                # Only process physical interfaces (xe-, ge-, etc.)
                if re.match(r'^(ge|xe|et|fe|gi|fa)', physical_interface):
                    device.interface_ae[physical_interface] = ae_interface
            
            # Also look for set format AE interface mappings
            set_ae_matches = re.findall(r'set interfaces (\S+) ether-options 802\.3ad (\S+)', content)
            for physical_interface, ae_interface in set_ae_matches:
                # Only process physical interfaces (xe-, ge-, etc.)
                if re.match(r'^(ge|xe|et|fe|gi|fa)', physical_interface):
                    device.interface_ae[physical_interface] = ae_interface
            
            # Extract VLAN information to map IRB interfaces to VLAN names and IDs
            vlan_irb_mapping = {}  # irb_unit: (vlan_name, vlan_id)
            device.vlan_irb_mapping = {}  # vlan_name: (irb_unit, vlan_id)
            vlan_section_match = re.search(r'vlans\s*{(.*)}', content, re.DOTALL)
            if vlan_section_match:
                vlan_content = vlan_section_match.group(1)
                # Find all VLAN definitions with l3-interface references
                vlan_matches = re.findall(r'(\w+)\s*{[^}]*vlan-id\s+(\d+);[^}]*l3-interface\s+irb\.(\d+);', vlan_content, re.DOTALL)
                for vlan_name, vlan_id, irb_unit in vlan_matches:
                    vlan_irb_mapping[irb_unit] = (vlan_name, vlan_id)
                    device.vlan_irb_mapping[vlan_name] = (irb_unit, vlan_id)
            
            # Extract trunk interface information
            # Look for trunk interfaces with vlan members
            # Try a simpler pattern to match the trunk interfaces in hierarchical format
            # First, find all interface blocks
            # Extract the interfaces section first
            interfaces_content = self._extract_interfaces_section(content)
            if interfaces_content:
                interface_blocks = self._extract_interface_blocks_from_section(interfaces_content)
                print(f"DEBUG: Found {len(interface_blocks)} interface blocks for trunk processing")
                for interface_name, interface_block in interface_blocks:
                    print(f"DEBUG: Processing interface {interface_name} for trunk detection")
                    # Look for trunk mode and vlan members within the interface block
                    # Updated pattern to match the actual nested configuration format
                    # Look for the nested structure: unit 0 { family ethernet-switching { interface-mode trunk; ... } }
                    # Fixed the regex to properly match the nested structure
                    trunk_match = re.search(r'unit\s+\d+\s*\{[^}]*?family\s+ethernet-switching\s*\{[^}]*?interface-mode\s+trunk;', interface_block, re.DOTALL)
                    if trunk_match:
                        print(f"DEBUG: Found trunk interface {interface_name}")
                        # Look for vlan members with a more precise pattern
                        # Handle both single VLAN and VLAN list formats
                        # Look for the nested structure: vlan { members ...; }
                        members_match = re.search(r'vlan\s*\{[^}]*?members\s+([^;]+?)\s*;', interface_block, re.DOTALL)
                        if members_match:
                            members_str = members_match.group(1).strip()
                            print(f"DEBUG: Found VLAN members for {interface_name}: {members_str}")
                            if members_str == "all":
                                device.trunk_interfaces[interface_name] = "all"
                            elif members_str.startswith("[") and members_str.endswith("]"):
                                # Parse list of VLANs
                                vlan_list = members_str.strip()[1:-1].strip().split()
                                device.trunk_interfaces[interface_name] = vlan_list
                            else:
                                # Single VLAN
                                device.trunk_interfaces[interface_name] = [members_str]
                        else:
                            print(f"DEBUG: No VLAN members found for trunk interface {interface_name}")
                            print(f"DEBUG: Interface block content: {repr(interface_block)}")
                    else:
                        # Look for access mode interfaces
                        access_match = re.search(r'unit\s+\d+\s*\{[^}]*?family\s+ethernet-switching\s*\{[^}]*?interface-mode\s+access;', interface_block, re.DOTALL)
                        if access_match:
                            print(f"DEBUG: Found access interface {interface_name}")
                            # Look for vlan members with a more precise pattern
                            # Handle single VLAN format
                            members_match = re.search(r'vlan\s*\{[^}]*?members\s+([^;]+?)\s*;', interface_block, re.DOTALL)
                            if members_match:
                                members_str = members_match.group(1).strip()
                                print(f"DEBUG: Found VLAN members for access interface {interface_name}: {members_str}")
                                # Store access VLAN information
                                if not hasattr(device, 'access_interfaces'):
                                    device.access_interfaces = {}
                                device.access_interfaces[interface_name] = members_str
                            else:
                                print(f"DEBUG: No VLAN members found for access interface {interface_name}")
                        else:
                            # Debug output to see what interfaces are not being matched
                            if interface_name.startswith("ae"):
                                print(f"DEBUG: AE interface {interface_name} not matched as trunk")
                                print(f"DEBUG: Interface block content: {repr(interface_block)}")
                                # Try a more specific pattern for AE interfaces
                                # Look for the exact pattern we see in the config files
                                ae_trunk_match = re.search(r'unit\s+0\s*\{[^}]*?family\s+ethernet-switching\s*\{[^}]*?interface-mode\s+trunk;', interface_block, re.DOTALL)
                                if ae_trunk_match:
                                    print(f"DEBUG: Found AE trunk interface {interface_name} with specific pattern")
                                    # Look for vlan members
                                    members_match = re.search(r'vlan\s*\{[^}]*?members\s+([^;]+?)\s*;', interface_block, re.DOTALL)
                                    if members_match:
                                        members_str = members_match.group(1).strip()
                                        print(f"DEBUG: Found VLAN members for AE trunk {interface_name}: {members_str}")
                                        if members_str == "all":
                                            device.trunk_interfaces[interface_name] = "all"
                                        elif members_str.startswith("[") and members_str.endswith("]"):
                                            # Parse list of VLANs
                                            vlan_list = members_str.strip()[1:-1].strip().split()
                                            device.trunk_interfaces[interface_name] = vlan_list
                                        else:
                                            # Single VLAN
                                            device.trunk_interfaces[interface_name] = [members_str]
                                    else:
                                        print(f"DEBUG: No VLAN members found for AE trunk {interface_name}")
                                        # Let's try a different pattern for the members
                                        members_match2 = re.search(r'members\s+([^;]+?);', interface_block, re.DOTALL)
                                        if members_match2:
                                            members_str = members_match2.group(1).strip()
                                            print(f"DEBUG: Found VLAN members with alternative pattern for {interface_name}: {members_str}")
                                            if members_str == "all":
                                                device.trunk_interfaces[interface_name] = "all"
                                            elif members_str.startswith("[") and members_str.endswith("]"):
                                                # Parse list of VLANs
                                                vlan_list = members_str.strip()[1:-1].strip().split()
                                                device.trunk_interfaces[interface_name] = vlan_list
                                            else:
                                                # Single VLAN
                                                device.trunk_interfaces[interface_name] = [members_str]
                                        else:
                                            print(f"DEBUG: Still no VLAN members found for {interface_name} with alternative pattern")
                                else:
                                    # Let's try an even more general pattern
                                    general_trunk_match = re.search(r'interface-mode\s+trunk;', interface_block)
                                    if general_trunk_match:
                                        print(f"DEBUG: Found general trunk interface {interface_name}")
                                        # Look for vlan members with the alternative pattern
                                        members_match = re.search(r'members\s+([^;]+?);', interface_block, re.DOTALL)
                                        if members_match:
                                            members_str = members_match.group(1).strip()
                                            print(f"DEBUG: Found VLAN members for general trunk {interface_name}: {members_str}")
                                            if members_str == "all":
                                                device.trunk_interfaces[interface_name] = "all"
                                            elif members_str.startswith("[") and members_str.endswith("]"):
                                                # Parse list of VLANs
                                                vlan_list = members_str.strip()[1:-1].strip().split()
                                                device.trunk_interfaces[interface_name] = vlan_list
                                            else:
                                                # Single VLAN
                                                device.trunk_interfaces[interface_name] = [members_str]
                                    else:
                                        print(f"DEBUG: AE interface {interface_name} not matched with any trunk pattern")
                                        # Let's check if it contains "interface-mode trunk" anywhere
                                        contains_trunk = "interface-mode trunk" in interface_block
                                        if contains_trunk:
                                            print(f"DEBUG: AE interface {interface_name} contains 'interface-mode trunk'")
                                            # Look for vlan members with the alternative pattern
                                            members_match = re.search(r'members\s+([^;]+?);', interface_block, re.DOTALL)
                                            if members_match:
                                                members_str = members_match.group(1).strip()
                                                print(f"DEBUG: Found VLAN members for AE trunk {interface_name}: {members_str}")
                                                if members_str == "all":
                                                    device.trunk_interfaces[interface_name] = "all"
                                                elif members_str.startswith("[") and members_str.endswith("]"):
                                                    # Parse list of VLANs
                                                    vlan_list = members_str.strip()[1:-1].strip().split()
                                                    device.trunk_interfaces[interface_name] = vlan_list
                                                else:
                                                    # Single VLAN
                                                    device.trunk_interfaces[interface_name] = [members_str]
                                            else:
                                                print(f"DEBUG: No VLAN members found for AE trunk {interface_name} with contains pattern")
            
            # Extract interface information
            # Handle both set format and hierarchical format
            
            # First, handle set format interfaces
            set_interface_lines = re.findall(r'set interfaces (\S+)(?:\s+(.*))?', content)
            interfaces_dict = {}
            
            # Group set format interface lines by interface name
            for interface_name, interface_details in set_interface_lines:
                if interface_name not in interfaces_dict:
                    interfaces_dict[interface_name] = []
                if interface_details:
                    interfaces_dict[interface_name].append(interface_details)
            
            # Then, handle hierarchical format interfaces
            # Find the main interfaces section (not in groups)
            print(f"Extracting interfaces section from content with {len(content)} characters")
            interfaces_content = self._extract_interfaces_section(content)
            if interfaces_content:
                print(f"Interfaces content length: {len(interfaces_content)}")
                
                # Find interface blocks with a more robust pattern
                # Use a proper nested brace matching approach
                interface_blocks = self._extract_interface_blocks_from_section(interfaces_content)
                for interface_name, interface_block_content in interface_blocks:
                    # Special handling for IRB interfaces
                    if interface_name == "irb":
                        # Extract IRB units
                        irb_units = self._extract_irb_units(interface_block_content)
                        for unit_num, unit_content in irb_units:
                            # Create proper IRB interface name like "irb0.78"
                            irb_interface_name = f"irb0.{unit_num}"
                            # Add to interfaces_dict
                            if irb_interface_name not in interfaces_dict:
                                interfaces_dict[irb_interface_name] = []
                            interfaces_dict[irb_interface_name].append(unit_content)
                    else:
                        # Add to interfaces_dict
                        if interface_name not in interfaces_dict:
                            interfaces_dict[interface_name] = []
                        interfaces_dict[interface_name].append(interface_block_content)
            
            # Process each interface
            for interface_name, interface_contents in interfaces_dict.items():
                # Skip internal interfaces and the original "irb" interface (IRB units are processed separately)
                if not re.match(r'^(ge|xe|et|fe|gi|fa|lo|irb|ae|fxp)', interface_name) or interface_name == "irb":
                    continue
                
                interface_content = " ".join(interface_contents)
                ip_addresses = []
                
                # Special handling for IRB interfaces - they already have the unit in their name
                if interface_name.startswith("irb0."):
                    # Extract IP addresses for IRB interfaces with proper ARP information
                    # Look for patterns like "address 10.0.123.1/24 {" and extract ARP entries
                    address_matches = re.finditer(r'address\s+([^\s;]+)(\s*\{[^}]*\})?', interface_content, re.DOTALL)
                    for address_match in address_matches:
                        ip_address = address_match.group(1).rstrip(';')
                        
                        # Get the unit number from the interface name
                        unit_num = interface_name.split('.')[1]
                        
                        # Check if this IRB unit is referenced in a VLAN
                        vlan_info = vlan_irb_mapping.get(unit_num, ("no-vlan", ""))
                        vlan_name, vlan_id = vlan_info
                        
                        # Format with VLAN information: irb0.78:vlan78<78>:10.0.78.1/30 or irb0.78:no-vlan:10.0.78.1/30
                        if vlan_id:
                            ip_addresses.append(f"{vlan_name}<{vlan_id}>:{ip_address}")
                        else:
                            ip_addresses.append(f"{vlan_name}:{ip_address}")
                        
                        # Check for ARP entries within the address block
                        address_block = address_match.group(2) or ""
                        if address_block:
                            arp_matches = re.findall(r'arp\s+([^\s]+)\s+l2-interface\s+([^\s]+)\s+mac\s+([^\s;]+)', address_block)
                            for arp_ip, l2_interface, mac in arp_matches:
                                ip_addresses.append(f" arp {arp_ip} l2-interface {l2_interface} mac {mac}")
                else:
                    # Extract IP addresses from unit configurations
                    # Look for patterns like "unit 0 { ... family inet { ... address 10.0.13.1/30;"
                    # Handle both set format and hierarchical format
                    
                    # First check for set format
                    set_unit_matches = re.finditer(r'set interfaces ' + re.escape(interface_name) + r' unit (\d+) family inet address ([^\s;]+)', content)
                    for set_unit_match in set_unit_matches:
                        unit_num = set_unit_match.group(1)
                        ip_address = set_unit_match.group(2)
                        # Format: .unit_num:ip_address
                        ip_addresses.append(f".{unit_num}:{ip_address}")
                    
                    # Then check for hierarchical format
                    unit_matches = re.finditer(r'unit\s+(\d+)\s*\{[^}]*family\s+inet\s*\{[^}]*address\s+([^\s;]+)', interface_content, re.DOTALL)
                    for unit_match in unit_matches:
                        unit_num = unit_match.group(1)
                        ip_address = unit_match.group(2).rstrip(';')  # Remove trailing semicolon if present
                        # Format: .unit_num:ip_address
                        ip_addresses.append(f".{unit_num}:{ip_address}")
                    
                    # If no IP addresses found in unit configurations, check for direct family inet address
                    if not ip_addresses:
                        ip_match = re.search(r'family\s+inet\s*\{[^}]*address\s+([^\s;]+)', interface_content, re.DOTALL)
                        if ip_match:
                            ip_address = ip_match.group(1).rstrip(';')  # Remove trailing semicolon if present
                            # Format: :ip_address (no unit)
                            ip_addresses.append(f":{ip_address}")
                
                if ip_addresses:
                    # Join IP addresses with newlines so each appears on a separate line
                    device.interfaces[interface_name] = "\n".join(ip_addresses)
                else:
                    device.interfaces[interface_name] = ""
                
        except Exception as e:
            print(f"Warning: Could not parse config file {config_file}: {e}")
            
        return device
    
    def _extract_interfaces_section(self, content: str) -> str:
        """Extract the interfaces section from the configuration content"""
        lines = content.split('\n')
        start_line = -1
        end_line = -1
        
        # Find the interfaces section - look for top-level 'interfaces {' 
        # We need to make sure we find the main interfaces section, not the one in groups or protocols lldp
        # Look for the main interfaces section by finding one that comes after system, chassis, etc.
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            
            # Look for 'interfaces {' at the top level (not indented)
            if stripped_line == 'interfaces {' and not line.startswith(' ') and not line.startswith('\t'):
                # Check if this is in a groups section by looking backwards
                in_groups = False
                for j in range(i-1, max(0, i-50), -1):  # Look back up to 50 lines
                    prev_line = lines[j].strip()
                    if prev_line.startswith('groups {'):
                        in_groups = True
                        break
                    elif prev_line.startswith('apply-groups'):
                        # We've found apply-groups, so this is likely the main config section
                        break
                
                if not in_groups:
                    start_line = i
                    break
        
        if start_line != -1:
            # Extract the content until the matching closing brace
            brace_count = 1
            content_lines = []
            for i in range(start_line + 1, len(lines)):
                line = lines[i]
                content_lines.append(line)
                
                # Count braces
                brace_count += line.count('{')
                brace_count -= line.count('}')
                
                if brace_count == 0:
                    end_line = i
                    break
            
            if end_line != -1:
                interfaces_content = '\n'.join(content_lines[:-1])  # Remove the last line which is the closing brace
                print(f"DEBUG: Found interfaces section with {len(interfaces_content)} characters")
                return interfaces_content
        else:
            print("DEBUG: Could not find interfaces section")
        
        return ""
    
    def _extract_interface_blocks_from_section(self, interfaces_content: str) -> list:
        """Extract interface blocks from the interfaces section"""
        interface_blocks = []
        lines = interfaces_content.split('\n')
        i = 0
        
        print(f"DEBUG: Processing interfaces content with {len(lines)} lines")
        
        while i < len(lines):
            line = lines[i].strip()
            print(f"DEBUG: Processing line {i}: '{line}'")
            # Look for interface name followed by opening brace
            # Make sure we're matching interface names like xe-0/0/1, ge-0/0/1, ae0, etc.
            # Handle both non-indented and indented lines
            interface_match = re.match(r'^(\w+[\w\-/]+)\s*{$', line)
            if interface_match:
                interface_name = interface_match.group(1)
                print(f"DEBUG: Found interface match: {interface_name}")
                # Only process actual interface names (xe-, ge-, ae-, irb, etc.)
                if re.match(r'^(ge|xe|et|fe|gi|fa|lo|irb|ae|fxp)', interface_name):
                    print(f"DEBUG: Processing interface block for {interface_name}")
                    # Extract the interface block content
                    brace_count = 1
                    block_lines = []
                    i += 1
                    
                    while i < len(lines) and brace_count > 0:
                        line = lines[i]
                        block_lines.append(line)
                        brace_count += line.count('{')
                        brace_count -= line.count('}')
                        i += 1
                    
                    # Remove the closing brace line
                    if block_lines and brace_count == 0:
                        block_lines = block_lines[:-1]
                    
                    interface_block_content = '\n'.join(block_lines)
                    print(f"DEBUG: Interface block content for {interface_name}: {len(interface_block_content)} characters")
                    interface_blocks.append((interface_name, interface_block_content))
                else:
                    # Skip this block as it's not an actual interface
                    print(f"DEBUG: Skipping non-interface block: {interface_name}")
                    brace_count = 1
                    i += 1
                    while i < len(lines) and brace_count > 0:
                        line = lines[i]
                        brace_count += line.count('{')
                        brace_count -= line.count('}')
                        i += 1
            else:
                i += 1
        
        print(f"DEBUG: Found {len(interface_blocks)} interface blocks")
        return interface_blocks
    
    def _extract_irb_units(self, irb_content: str) -> list:
        """Extract IRB unit blocks from IRB interface content"""
        unit_blocks = []
        lines = irb_content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            # Look for unit number followed by opening brace
            unit_match = re.match(r'^unit\s+(\d+)\s*{$', line)
            if unit_match:
                unit_num = unit_match.group(1)
                
                # Extract the unit block content
                brace_count = 1
                block_lines = []
                i += 1
                
                while i < len(lines) and brace_count > 0:
                    line = lines[i]
                    block_lines.append(line)
                    brace_count += line.count('{')
                    brace_count -= line.count('}')
                    i += 1
                
                # Remove the closing brace line
                if block_lines and brace_count == 0:
                    block_lines = block_lines[:-1]
                
                unit_block_content = '\n'.join(block_lines)
                unit_blocks.append((unit_num, unit_block_content))
            else:
                i += 1
        
        return unit_blocks
    
    def parse_lldp_file(self, lldp_file: Path) -> List[Tuple[str, str, str]]:
        """Parse LLDP neighbor information from JSON file"""
        neighbors = []
        
        try:
            with open(lldp_file, 'r') as f:
                # Handle files that might have multiple JSON objects or extra text
                content = f.read()
                
                # Try to parse as JSON directly first
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    # If that fails, try to find JSON object in the content
                    # Look for the start of a JSON object
                    json_start = content.find('{')
                    if json_start != -1:
                        # Try to parse from the first { onwards
                        try:
                            data = json.loads(content[json_start:])
                        except json.JSONDecodeError:
                            print(f"Warning: Could not parse LLDP file {lldp_file}")
                            return neighbors
                    else:
                        print(f"Warning: Could not find JSON in LLDP file {lldp_file}")
                        return neighbors
                
            # Extract neighbor information
            if 'lldp-neighbors-information' in data:
                neighbors_info = data['lldp-neighbors-information']
                if isinstance(neighbors_info, list):
                    neighbors_list = neighbors_info
                else:
                    neighbors_list = [neighbors_info]
                    
                for neighbor_block in neighbors_list:
                    if 'lldp-neighbor-information' in neighbor_block:
                        neighbor_details = neighbor_block['lldp-neighbor-information']
                        if isinstance(neighbor_details, list):
                            # Multiple neighbors in one block
                            for neighbor in neighbor_details:
                                # Use lldp-local-interface for the actual interface name, fallback to lldp-local-port-id
                                local_interface = self._extract_value_from_lldp_data(neighbor.get('lldp-local-interface', ''))
                                if not local_interface:
                                    local_interface = self._extract_value_from_lldp_data(neighbor.get('lldp-local-port-id', ''))
                                remote_system = self._extract_value_from_lldp_data(neighbor.get('lldp-remote-system-name', ''))
                                # Use lldp-remote-port-description for the remote interface name if available, 
                                # otherwise fall back to lldp-remote-port-id
                                remote_port_desc = self._extract_value_from_lldp_data(neighbor.get('lldp-remote-port-description', ''))
                                remote_port_id = self._extract_value_from_lldp_data(neighbor.get('lldp-remote-port-id', ''))
                                remote_port = remote_port_desc if remote_port_desc else remote_port_id
                                
                                # Preserve the full remote system name as it appears in the LLDP data
                                # Only remove domain part (.englab.juniper.net) and strip whitespace
                                if remote_system:
                                    # Extract hostname from FQDN if needed (only remove domain part)
                                    if '.' in remote_system:
                                        remote_system = remote_system.split('.')[0]
                                    # Only strip whitespace
                                    remote_system = remote_system.strip()
                                    
                                    if local_interface and remote_port:
                                        neighbors.append((local_interface, remote_system, remote_port))
                        else:
                            # Single neighbor
                            # Use lldp-local-interface for the actual interface name, fallback to lldp-local-port-id
                            local_interface = self._extract_value_from_lldp_data(neighbor_details.get('lldp-local-interface', ''))
                            if not local_interface:
                                local_interface = self._extract_value_from_lldp_data(neighbor_details.get('lldp-local-port-id', ''))
                            remote_system = self._extract_value_from_lldp_data(neighbor_details.get('lldp-remote-system-name', ''))
                            # Use lldp-remote-port-description for the remote interface name if available, 
                            # otherwise fall back to lldp-remote-port-id
                            remote_port_desc = self._extract_value_from_lldp_data(neighbor_details.get('lldp-remote-port-description', ''))
                            remote_port_id = self._extract_value_from_lldp_data(neighbor_details.get('lldp-remote-port-id', ''))
                            remote_port = remote_port_desc if remote_port_desc else remote_port_id
                            
                            # Preserve the full remote system name as it appears in the LLDP data
                            # Only remove domain part (.englab.juniper.net) and strip whitespace
                            if remote_system:
                                # Extract hostname from FQDN if needed (only remove domain part)
                                if '.' in remote_system:
                                    remote_system = remote_system.split('.')[0]
                                # Only strip whitespace
                                remote_system = remote_system.strip()
                                
                                if local_interface and remote_port:
                                    neighbors.append((local_interface, remote_system, remote_port))
                                    
        except Exception as e:
            print(f"Warning: Could not parse LLDP file {lldp_file}: {e}")
            
        return neighbors
    
    def _extract_value_from_lldp_data(self, data_field) -> str:
        """Extract string value from LLDP data field which may be a list or dict"""
        try:
            if isinstance(data_field, list):
                if len(data_field) > 0:
                    first_item = data_field[0]
                    if isinstance(first_item, dict) and 'data' in first_item:
                        return str(first_item['data']).strip()
                    else:
                        return str(first_item).strip()
                else:
                    return ''
            elif isinstance(data_field, dict):
                if 'data' in data_field:
                    return str(data_field['data']).strip()
                else:
                    return str(data_field).strip()
            else:
                return str(data_field).strip()
        except Exception:
            return ''
    
    def build_topology(self):
        """Build network topology from configuration and LLDP files"""
        # Parse configuration files
        config_files = list(self.config_dir.glob("*.txt"))
        for config_file in config_files:
            if '-config' in config_file.name:
                print(f"DEBUG: Processing config file {config_file.name}")
                device = self.parse_config_file(config_file)
                print(f"DEBUG: Device {device.name} has {len(device.trunk_interfaces)} trunk interfaces")
                # Print trunk interfaces for debugging
                for interface_name, vlan_members in device.trunk_interfaces.items():
                    print(f"DEBUG: Trunk interface {interface_name}: {vlan_members}")
                # Print VLAN mapping for debugging
                for vlan_name, (irb_unit, vlan_id) in device.vlan_irb_mapping.items():
                    print(f"DEBUG: VLAN mapping {vlan_name} -> IRB unit {irb_unit}, VLAN ID {vlan_id}")
                self.devices[device.name] = device
        
        # Parse LLDP files
        lldp_files = list(self.lldp_dir.glob("*.txt"))
        for lldp_file in lldp_files:
            if '-lldp' in lldp_file.name or 'json-detail-lldp' in lldp_file.name:
                neighbors = self.parse_lldp_file(lldp_file)
                
                # Associate neighbors with devices
                # Extract device name from filename
                device_name = self.extract_hostname_from_filename(lldp_file.name)
                if device_name in self.devices:
                    self.devices[device_name].neighbors.extend(neighbors)
        
        # Build connection map
        # Create a map of all connections to avoid duplicates
        connection_map = defaultdict(list)
        
        for device_name, device in self.devices.items():
            for local_port, remote_device, remote_port in device.neighbors:
                # Create a consistent key for each connection
                connection_key = tuple(sorted([(device_name, local_port), (remote_device, remote_port)]))
                connection_map[connection_key].append((device_name, local_port, remote_device, remote_port))
        
        # Add connections to the topology
        # Only add each connection once
        for connection_key, connection_list in connection_map.items():
            # Use the first connection in the list
            dev1, port1, dev2, port2 = connection_list[0]
            self.connections.add((dev1, port1, dev2, port2))
    
    def calculate_layout(self):
        """Calculate device positions for layout with improved connection routing and alignment"""
        if not self.devices:
            return
            
        # Count connections per device
        connection_count = defaultdict(int)
        for dev1, port1, dev2, port2 in self.connections:
            connection_count[dev1] += 1
            connection_count[dev2] += 1
        
        # Find devices with maximum connections (core devices)
        max_connections = max(connection_count.values()) if connection_count else 0
        center_devices = [name for name, count in connection_count.items() if count == max_connections]
        
        # Sort center devices alphabetically
        center_devices.sort()
        
        # Separate devices by type and connection count
        routers = []
        switches = []
        unknowns = []
        
        # Categorize devices
        for name, device in self.devices.items():
            if name not in center_devices:
                if device.device_type == 'router':
                    routers.append(name)
                elif device.device_type == 'switch':
                    switches.append(name)
                else:
                    unknowns.append(name)
        
        # Sort by connection count (descending) then alphabetically
        routers.sort(key=lambda x: (-connection_count.get(x, 0), x))
        switches.sort(key=lambda x: (-connection_count.get(x, 0), x))
        unknowns.sort(key=lambda x: (-connection_count.get(x, 0), x))
        
        # Calculate positions with improved layout to avoid crossing connections
        center_y = 200
        router_y = 80
        switch_y = 320
        unknown_y = 440
        
        # Fixed horizontal spacing for consistent alignment
        x_spacing = 180
        start_x = 100  # Starting x position for all rows to ensure left alignment
        
        # Position center devices (core) - left-aligned like other rows
        center_start_x = start_x
        for device_name in center_devices:
            if device_name in self.devices:
                self.devices[device_name].position = (center_start_x, center_y)
                center_start_x += x_spacing
        
        # Optimize router positioning to minimize connection crossings
        if routers:
            optimized_routers = self._minimize_crossings(routers, center_devices, router_y)
            router_start_x = start_x
            for device_name in optimized_routers:
                if device_name in self.devices:
                    self.devices[device_name].position = (router_start_x, router_y)
                    router_start_x += x_spacing
        
        # Optimize switch positioning to minimize connection crossings
        if switches:
            optimized_switches = self._minimize_crossings(switches, center_devices, switch_y)
            switch_start_x = start_x
            for device_name in optimized_switches:
                if device_name in self.devices:
                    self.devices[device_name].position = (switch_start_x, switch_y)
                    switch_start_x += x_spacing
        
        # Position unknown devices below switches - left-aligned
        unknown_start_x = start_x
        for device_name in unknowns:
            if device_name in self.devices:
                self.devices[device_name].position = (unknown_start_x, unknown_y)
                unknown_start_x += x_spacing
    
    def _count_crossings(self, device_order, target_devices):
        """Count the number of connection crossings for a given device order"""
        # Create position mapping for target devices
        target_positions = {name: i for i, name in enumerate(target_devices)}
        
        # Count crossings between connections
        crossings = 0
        connections = []
        
        # Get all connections for devices in this row to target devices
        for device_name in device_order:
            device_connections = []
            for target_name in target_devices:
                # Check connections in both directions
                for conn in self.connections:
                    if (conn[0] == device_name and conn[2] == target_name) or \
                       (conn[0] == target_name and conn[2] == device_name):
                        device_connections.append(target_name)
                        break
            # Sort connections by target position
            device_connections.sort(key=lambda x: target_positions.get(x, 0))
            connections.append((device_name, device_connections))
        
        # Count crossings between adjacent devices
        for i in range(len(connections)):
            for j in range(i + 1, len(connections)):
                device1, conns1 = connections[i]
                device2, conns2 = connections[j]
                
                # Count crossings between connections of device1 and device2
                for target1 in conns1:
                    pos1 = target_positions.get(target1, 0)
                    for target2 in conns2:
                        pos2 = target_positions.get(target2, 0)
                        # If connection from device1 to target1 crosses connection from device2 to target2
                        if pos1 > pos2:
                            crossings += 1
        
        return crossings
    
    def _minimize_crossings(self, devices, target_devices, y_level):
        """Minimize connection crossings by reordering devices"""
        if not devices or not target_devices:
            return devices
        
        # If only one device, no crossings possible
        if len(devices) <= 1:
            return devices
        
        # Try different orderings to minimize crossings
        best_order = devices[:]
        min_crossings = self._count_crossings(best_order, target_devices)
        
        # Try a few permutations to find a better ordering
        import itertools
        for perm in itertools.islice(itertools.permutations(devices), min(24, len(devices) * 2)):  # Limit permutations for performance
            crossings = self._count_crossings(list(perm), target_devices)
            if crossings < min_crossings:
                min_crossings = crossings
                best_order = list(perm)
        
        return best_order
    
    def _distribute_devices_horizontally(self, devices, start_x, spacing, y_level):
        """Distribute devices horizontally with consistent left alignment"""
        if not devices:
            return []
            
        positions = []
        # Always start from the same x position for consistent left alignment
        current_pos = start_x
        for i in range(len(devices)):
            positions.append(current_pos)
            current_pos += spacing
                
        return positions


class DrawIOGenerator:
    """Generate DrawIO XML for network topology diagram"""
    
    def __init__(self, args=None):
        self.next_id = 2  # Start from 2 since 0 and 1 are reserved by DrawIO
        self.device_id_map = {}  # Map device names to DrawIO IDs
        self.device_positions = {}  # Map device names to their center positions
        self.topology = None  # Reference to topology builder for accessing device information
        self.args = args  # Command line arguments for IPv4 option
    
    def register_device_position(self, device_name: str, center: tuple):
        """Register device center position for label placement"""
        self.device_positions[device_name] = center
    
    def calculate_connection_angle(self, pos1: tuple, pos2: tuple) -> float:
        """Calculate angle between two device positions"""
        dx = pos2[0] - pos1[0]
        dy = pos2[1] - pos1[1]
        return math.atan2(dy, dx)
    
    def calculate_connection_orientation(self, dev1: str, dev2: str) -> str:
        """Calculate the orientation of connection between two devices"""
        # Get device types to determine likely orientation
        dev1_type = self.get_device_type_from_name(dev1)
        dev2_type = self.get_device_type_from_name(dev2)
        
        # Special case: vqfx1 to vqfx3 should be treated as vertical (same as vmx1 to vqfx1)
        if (dev1 == "vqfx1" and dev2 == "vqfx3") or (dev1 == "vqfx3" and dev2 == "vqfx1"):
            return "vertical"
        
        # If both devices are of same type, it's likely horizontal
        if dev1_type == dev2_type:
            return "horizontal"
        # If one is router and one is switch, it's likely vertical or diagonal
        elif (dev1_type == "router" and dev2_type == "switch") or (dev1_type == "switch" and dev2_type == "router"):
            return "vertical"
        else:
            return "diagonal"
    
    def get_device_type_from_name(self, device_name: str) -> str:
        """Determine device type from name pattern"""
        if 'vmx' in device_name.lower() or 'mx' in device_name.lower():
            return "router"
        elif 'vqfx' in device_name.lower() or 'qfx' in device_name.lower():
            return "switch"
        else:
            return "unknown"
    
    def get_optimized_label_positions(self, dev1: str, port1: str, dev2: str, port2: str, 
                                     connection_index: int, total_connections: int) -> tuple:
        """
        Calculate optimized label positions that are closer to connection endpoints,
        with consistent rules and minimal overlap.
        """
        # Simple rule: All interface labels placed above the connection endpoints and center-aligned
        source_x_offset = 0    # Center-aligned horizontally
        source_y_offset = -10  # Above the connection endpoint
        target_x_offset = 0    # Center-aligned horizontally
        target_y_offset = -10  # Above the connection endpoint
        
        return (source_x_offset, source_y_offset, target_x_offset, target_y_offset)
    
    def create_connection_line(self, dev1: str, port1: str, dev2: str, port2: str, connection_index: int = 0, total_connections: int = 1) -> str:
        """Create XML for connection line with interface labels at both ends and straight line routing"""
        source_id = self.get_device_id(dev1)
        target_id = self.get_device_id(dev2)
        
        # Ensure both devices exist in our mapping
        if dev1 not in self.device_id_map or dev2 not in self.device_id_map:
            return ""
        
        edge_id = str(self.next_id)
        self.next_id += 1
        
        # Determine connection color based on interface speeds
        port1_color = self.get_interface_speed_color(port1)
        port2_color = self.get_interface_speed_color(port2)
        
        color_priority = {
            '#00cc00': 5,  # 400G green
            '#ffcc00': 4,  # 100G yellow
            '#0066cc': 3,  # 40G blue
            '#ff0000': 2,  # 10G red
            '#000000': 1   # 1G black
        }
        
        # Choose the higher priority color
        connection_color = port1_color if color_priority.get(port1_color, 0) >= color_priority.get(port2_color, 0) else port2_color
        
        # Get device positions to determine connection direction and routing
        dev1_pos = self.device_positions.get(dev1, (0, 0))
        dev2_pos = self.device_positions.get(dev2, (0, 0))
        
        # Determine optimal exit/entry points for straight lines
        exit_x, exit_y, entry_x, entry_y = self._calculate_straight_line_connection_points(dev1, dev2, dev1_pos, dev2_pos, connection_index, total_connections)
        
        # Create connection line with straight line routing (no edgeStyle for straight lines)
        connection_line = f'''<mxCell id="{edge_id}" value="" style="endArrow=none;html=1;rounded=0;strokeColor={connection_color};strokeWidth=1;exitX={exit_x};exitY={exit_y};exitDx=0;exitDy=0;entryX={entry_x};entryY={entry_y};entryDx=0;entryDy=0;" edge="1" parent="1" source="{source_id}" target="{target_id}">
            <mxGeometry relative="1" as="geometry"/>
        </mxCell>'''
        
        # Create interface labels at both ends
        # Source label (at start of connection)
        source_label_id = str(self.next_id)
        self.next_id += 1
        
        # Target label (at end of connection)
        target_label_id = str(self.next_id)
        self.next_id += 1
        
        # Build source label content
        source_label_parts = [port1]  # Start with interface name only
        
        # Join label parts with HTML line breaks
        source_label_content = self._escape_xml("<br>".join(source_label_parts))
        
        source_label = f'''<mxCell id="{source_label_id}" value="{source_label_content}" style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#666666;fillColor=none;labelBackgroundColor=none;" vertex="1" connectable="0" parent="{edge_id}">
            <mxGeometry x="-0.9" relative="1" as="geometry">
                <mxPoint x="0" y="-4" as="offset"/>
            </mxGeometry>
        </mxCell>'''
        
        # Build target label content in the same way
        target_label_parts = [port2]  # Start with interface name only
    
        # Join label parts with HTML line breaks
        target_label_content = self._escape_xml("<br>".join(target_label_parts))
    
        target_label = f'''<mxCell id="{target_label_id}" value="{target_label_content}" style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#666666;fillColor=none;labelBackgroundColor=none;" vertex="1" connectable="0" parent="{edge_id}">
            <mxGeometry x="0.9" relative="1" as="geometry">
                <mxPoint x="0" y="-4" as="offset"/>
            </mxGeometry>
        </mxCell>'''
    
        return connection_line + source_label + target_label
    
    def _calculate_straight_line_connection_points(self, dev1: str, dev2: str, pos1: tuple, pos2: tuple, connection_index: int, total_connections: int) -> tuple:
        """Calculate optimal connection points for straight line routing with support for multiple connections
        
        Implements three routing strategies based on device positioning:
        1. Horizontal separation with Y overlap → horizontal shortest straight line with evenly distributed points
        2. Vertical separation with X overlap → vertical shortest straight line with evenly distributed points
        3. Diagonal separation (no X/Y overlap) → nearest corner-to-corner connection with equal spacing
        """
        # Device dimensions (80x60)
        device_width = 80
        device_height = 60
        
        # Calculate device boundaries
        dev1_left = pos1[0]
        dev1_right = pos1[0] + device_width
        dev1_top = pos1[1]
        dev1_bottom = pos1[1] + device_height
        
        dev2_left = pos2[0]
        dev2_right = pos2[0] + device_width
        dev2_top = pos2[1]
        dev2_bottom = pos2[1] + device_height
        
        # Check for overlap in X and Y dimensions
        x_overlap = max(0, min(dev1_right, dev2_right) - max(dev1_left, dev2_left))
        y_overlap = max(0, min(dev1_bottom, dev2_bottom) - max(dev1_top, dev2_top))
        
        # Determine separation type
        horizontal_separation = dev1_right < dev2_left or dev2_right < dev1_left
        vertical_separation = dev1_bottom < dev2_top or dev2_bottom < dev1_top
        
        # Helper function to create linspace without numpy
        def linspace(start, stop, num):
            if num <= 0:
                return []
            elif num == 1:
                return [start]
            else:
                step = (stop - start) / (num - 1)
                return [start + i * step for i in range(num)]
        
        if horizontal_separation and y_overlap > 0:
            # Horizontal separation with Y overlap
            # Use horizontal shortest straight line (left device right edge ↔ right device left edge)
            # Distribute points evenly in the Y overlap area
            
            # Determine which device is on the left
            if dev1_left < dev2_left:
                left_device_right_edge = 1.0  # Right edge of left device (normalized)
                right_device_left_edge = 0.0  # Left edge of right device (normalized)
                exit_device = "dev1"
                entry_device = "dev2"
            else:
                left_device_right_edge = 0.0  # Left edge of right device (normalized)
                right_device_left_edge = 1.0  # Right edge of left device (normalized)
                exit_device = "dev2"
                entry_device = "dev1"
            
            # Calculate Y overlap range
            y_overlap_start = max(dev1_top, dev2_top)
            y_overlap_end = min(dev1_bottom, dev2_bottom)
            
            # Normalize Y positions to device coordinates (0-1)
            y_overlap_start_norm1 = (y_overlap_start - dev1_top) / device_height
            y_overlap_end_norm1 = (y_overlap_end - dev1_top) / device_height
            y_overlap_start_norm2 = (y_overlap_start - dev2_top) / device_height
            y_overlap_end_norm2 = (y_overlap_end - dev2_top) / device_height
            
            if total_connections == 1:
                # Single connection at midpoint of overlap
                exit_y = (y_overlap_start_norm1 + y_overlap_end_norm1) / 2
                entry_y = (y_overlap_start_norm2 + y_overlap_end_norm2) / 2
                exit_x = left_device_right_edge
                entry_x = right_device_left_edge
            else:
                # Multiple connections, distribute evenly in overlap area
                # Create evenly spaced points in the overlap region, but reduce spacing by 3/4
                # Move the distribution range toward the center by 3/8 on each side
                range_reduction = 0.375  # Reduce range by 3/8 on each side (total 3/4 reduction)
                reduced_y_start_norm1 = y_overlap_start_norm1 + (y_overlap_end_norm1 - y_overlap_start_norm1) * range_reduction
                reduced_y_end_norm1 = y_overlap_end_norm1 - (y_overlap_end_norm1 - y_overlap_start_norm1) * range_reduction
                reduced_y_start_norm2 = y_overlap_start_norm2 + (y_overlap_end_norm2 - y_overlap_start_norm2) * range_reduction
                reduced_y_end_norm2 = y_overlap_end_norm2 - (y_overlap_end_norm2 - y_overlap_start_norm2) * range_reduction
                
                y_positions_norm1 = linspace(reduced_y_start_norm1, reduced_y_end_norm1, total_connections)
                y_positions_norm2 = linspace(reduced_y_start_norm2, reduced_y_end_norm2, total_connections)
                
                # Select position based on connection index
                pos_idx = min(connection_index, len(y_positions_norm1) - 1)
                exit_y = y_positions_norm1[pos_idx]
                entry_y = y_positions_norm2[pos_idx]
                exit_x = left_device_right_edge
                entry_x = right_device_left_edge
                
        elif vertical_separation and x_overlap > 0:
            # Vertical separation with X overlap
            # Use vertical shortest straight line (upper device bottom edge ↔ lower device top edge)
            # Distribute points evenly in the X overlap area
            
            # Determine which device is on top
            if dev1_top < dev2_top:
                top_device_bottom_edge = 1.0  # Bottom edge of top device (normalized)
                bottom_device_top_edge = 0.0  # Top edge of bottom device (normalized)
                exit_device = "dev1"
                entry_device = "dev2"
            else:
                top_device_bottom_edge = 0.0  # Top edge of bottom device (normalized)
                bottom_device_top_edge = 1.0  # Bottom edge of top device (normalized)
                exit_device = "dev2"
                entry_device = "dev1"
            
            # Calculate X overlap range
            x_overlap_start = max(dev1_left, dev2_left)
            x_overlap_end = min(dev1_right, dev2_right)
            
            # Normalize X positions to device coordinates (0-1)
            x_overlap_start_norm1 = (x_overlap_start - dev1_left) / device_width
            x_overlap_end_norm1 = (x_overlap_end - dev1_left) / device_width
            x_overlap_start_norm2 = (x_overlap_start - dev2_left) / device_width
            x_overlap_end_norm2 = (x_overlap_end - dev2_left) / device_width
            
            if total_connections == 1:
                # Single connection at midpoint of overlap
                exit_x = (x_overlap_start_norm1 + x_overlap_end_norm1) / 2
                entry_x = (x_overlap_start_norm2 + x_overlap_end_norm2) / 2
                exit_y = top_device_bottom_edge
                entry_y = bottom_device_top_edge
            else:
                # Multiple connections, distribute evenly in overlap area
                # Create evenly spaced points in the overlap region, but reduce spacing by 3/4
                # Move the distribution range toward the center by 3/8 on each side
                range_reduction = 0.375  # Reduce range by 3/8 on each side (total 3/4 reduction)
                reduced_x_start_norm1 = x_overlap_start_norm1 + (x_overlap_end_norm1 - x_overlap_start_norm1) * range_reduction
                reduced_x_end_norm1 = x_overlap_end_norm1 - (x_overlap_end_norm1 - x_overlap_start_norm1) * range_reduction
                reduced_x_start_norm2 = x_overlap_start_norm2 + (x_overlap_end_norm2 - x_overlap_start_norm2) * range_reduction
                reduced_x_end_norm2 = x_overlap_end_norm2 - (x_overlap_end_norm2 - x_overlap_start_norm2) * range_reduction
                
                x_positions_norm1 = linspace(reduced_x_start_norm1, reduced_x_end_norm1, total_connections)
                x_positions_norm2 = linspace(reduced_x_start_norm2, reduced_x_end_norm2, total_connections)
                
                # Select position based on connection index
                pos_idx = min(connection_index, len(x_positions_norm1) - 1)
                exit_x = x_positions_norm1[pos_idx]
                entry_x = x_positions_norm2[pos_idx]
                exit_y = top_device_bottom_edge
                entry_y = bottom_device_top_edge
                
        elif horizontal_separation and vertical_separation:
            # Diagonal separation (no X/Y overlap)
            # Use nearest corner-to-corner connection with equal spacing along edges
            
            # Determine relative positions
            dev1_is_left = dev1_left < dev2_left
            dev1_is_above = dev1_top < dev2_top
            
            if dev1_is_left and dev1_is_above:
                # dev1 is upper-left of dev2
                exit_x, exit_y = 1.0, 1.0  # Bottom-right corner of dev1
                entry_x, entry_y = 0.0, 0.0  # Top-left corner of dev2
            elif dev1_is_left and not dev1_is_above:
                # dev1 is lower-left of dev2
                exit_x, exit_y = 1.0, 0.0  # Top-right corner of dev1
                entry_x, entry_y = 0.0, 1.0  # Bottom-left corner of dev2
            elif not dev1_is_left and dev1_is_above:
                # dev1 is upper-right of dev2
                exit_x, exit_y = 0.0, 1.0  # Bottom-left corner of dev1
                entry_x, entry_y = 1.0, 0.0  # Top-right corner of dev2
            else:
                # dev1 is lower-right of dev2
                exit_x, exit_y = 0.0, 0.0  # Top-left corner of dev1
                entry_x, entry_y = 1.0, 1.0  # Bottom-right corner of dev2
            
            # For multiple connections, offset along edges with equal spacing
            if total_connections > 1:
                # Define edge offset directions based on corner used
                if exit_x == 1.0 and exit_y == 1.0:  # Bottom-right corner
                    exit_offset_x, exit_offset_y = -1.0, 0.0  # Move left along bottom edge
                elif exit_x == 1.0 and exit_y == 0.0:  # Top-right corner
                    exit_offset_x, exit_offset_y = 0.0, 1.0  # Move down along right edge
                elif exit_x == 0.0 and exit_y == 1.0:  # Bottom-left corner
                    exit_offset_x, exit_offset_y = 1.0, 0.0  # Move right along bottom edge
                else:  # Top-left corner
                    exit_offset_x, exit_offset_y = 0.0, 1.0  # Move down along left edge
                
                if entry_x == 1.0 and entry_y == 1.0:  # Bottom-right corner
                    entry_offset_x, entry_offset_y = -1.0, 0.0  # Move left along bottom edge
                elif entry_x == 1.0 and entry_y == 0.0:  # Top-right corner
                    entry_offset_x, entry_offset_y = 0.0, 1.0  # Move down along right edge
                elif entry_x == 0.0 and entry_y == 1.0:  # Bottom-left corner
                    entry_offset_x, entry_offset_y = 1.0, 0.0  # Move right along bottom edge
                else:  # Top-left corner
                    entry_offset_x, entry_offset_y = 0.0, 1.0  # Move down along left edge
                
                # Calculate offset amount (limit to prevent going off device edges)
                max_offset = 0.3  # Maximum offset as fraction of device dimension
                offset_step = max_offset / max(total_connections - 1, 1)
                offset_amount = min(connection_index * offset_step, max_offset)
                
                # Apply offsets
                exit_x = max(0.0, min(1.0, exit_x + exit_offset_x * offset_amount))
                exit_y = max(0.0, min(1.0, exit_y + exit_offset_y * offset_amount))
                entry_x = max(0.0, min(1.0, entry_x + entry_offset_x * offset_amount))
                entry_y = max(0.0, min(1.0, entry_y + entry_offset_y * offset_amount))
                
        else:
            # Fallback to original algorithm for edge cases
            # Calculate vector from center1 to center2
            dx = (dev2_left + device_width/2) - (dev1_left + device_width/2)
            dy = (dev2_top + device_height/2) - (dev1_top + device_height/2)
            
            # For single connection, calculate the shortest straight line between device edges
            if total_connections == 1:
                # Calculate exit point on device1 (normalized coordinates 0-1)
                if abs(dx) > abs(dy):  # More horizontal connection
                    if dx > 0:  # Device2 is to the right of device1
                        exit_x = 1.0
                        exit_y = 0.5
                    else:  # Device2 is to the left of device1
                        exit_x = 0.0
                        exit_y = 0.5
                else:  # More vertical connection
                    if dy > 0:  # Device2 is below device1
                        exit_x = 0.5
                        exit_y = 1.0
                    else:  # Device2 is above device1
                        exit_x = 0.5
                        exit_y = 0.0
                
                # Calculate entry point on device2 (opposite side)
                if abs(dx) > abs(dy):  # More horizontal connection
                    if dx > 0:  # Device2 is to the right of device1
                        entry_x = 0.0
                        entry_y = 0.5
                    else:  # Device2 is to the left of device1
                        entry_x = 1.0
                        entry_y = 0.5
                else:  # More vertical connection
                    if dy > 0:  # Device2 is below device1
                        entry_x = 0.5
                        entry_y = 0.0
                    else:  # Device2 is above device1
                        entry_x = 0.5
                        entry_y = 1.0
                        
            else:
                # For multiple connections between the same devices, calculate different edge points
                # to make them parallel rather than crossing
                
                # Determine which side of the devices to connect based on relative positions
                if abs(dx) > abs(dy):  # More horizontal connection
                    if dx > 0:  # Device2 is to the right of device1
                        exit_x = 1.0
                        entry_x = 0.0
                        # Distribute connections vertically along the right edge of device1 and left edge of device2
                        edge_positions = [0.2, 0.5, 0.8]  # Top, middle, bottom positions
                        pos_idx = min(connection_index, len(edge_positions) - 1)
                        exit_y = edge_positions[pos_idx]
                        entry_y = edge_positions[pos_idx]
                    else:  # Device2 is to the left of device1
                        exit_x = 0.0
                        entry_x = 1.0
                        # Distribute connections vertically along the left edge of device1 and right edge of device2
                        edge_positions = [0.2, 0.5, 0.8]  # Top, middle, bottom positions
                        pos_idx = min(connection_index, len(edge_positions) - 1)
                        exit_y = edge_positions[pos_idx]
                        entry_y = edge_positions[pos_idx]
                else:  # More vertical connection
                    if dy > 0:  # Device2 is below device1
                        exit_y = 1.0
                        entry_y = 0.0
                        # Distribute connections horizontally along the bottom edge of device1 and top edge of device2
                        edge_positions = [0.2, 0.5, 0.8]  # Left, middle, right positions
                        pos_idx = min(connection_index, len(edge_positions) - 1)
                        exit_x = edge_positions[pos_idx]
                        entry_x = edge_positions[pos_idx]
                    else:  # Device2 is above device1
                        exit_y = 0.0
                        entry_y = 1.0
                        # Distribute connections horizontally along the top edge of device1 and bottom edge of device2
                        edge_positions = [0.2, 0.5, 0.8]  # Left, middle, right positions
                        pos_idx = min(connection_index, len(edge_positions) - 1)
                        exit_x = edge_positions[pos_idx]
                        entry_x = edge_positions[pos_idx]
        
        return (exit_x, exit_y, entry_x, entry_y)
    
    def _create_ip_info_elements(self, topology: TopologyBuilder) -> list:
        """Create IP information elements for DrawIO diagram with improved collision detection"""
        ip_elements = []
        spatial_index = SpatialIndex(2000, 2000)  # Increased size for better placement
        
        # Find current diagram bottom to position text boxes correctly
        diagram_bottom_y = 50  # Start below the main diagram
        
        # Calculate connection IP information first
        connection_lines = ["link IP Info", ""]  # Add empty line after title
        
        # Sort connections with smaller hostname first in each connection
        sorted_connections = []
        for dev1, port1, dev2, port2 in topology.connections:
            # Ensure smaller hostname is first
            if dev1 <= dev2:
                sorted_connections.append((dev1, port1, dev2, port2))
            else:
                sorted_connections.append((dev2, port2, dev1, port1))
        # Sort the connections
        sorted_connections.sort()
        
        # Group connections by device pairs for AE interface handling
        connection_groups = defaultdict(list)
        for dev1, port1, dev2, port2 in sorted_connections:
            device_pair = tuple(sorted([dev1, dev2]))
            connection_groups[device_pair].append((dev1, port1, dev2, port2))
        
        connection_index = 1
        for device_pair, connections in connection_groups.items():
            dev1, port1, dev2, port2 = connections[0]
            if len(connections) == 1:
                # Single connection
                device1 = topology.devices[dev1]
                device2 = topology.devices[dev2]
                ip1 = device1.interfaces.get(port1, "")
                ip2 = device2.interfaces.get(port2, "")
                
                if ip1 or ip2:
                    # Format interface list with hostnames
                    if ip1:
                        # Remove leading newlines and format properly
                        ip1_clean = ip1.lstrip("\n")
                        # Extract the IP part correctly
                        if ":" in ip1_clean:
                            # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                            ip1_part = ip1_clean.split(":")[-1]
                        else:
                            ip1_part = ip1_clean
                        ip1_display = f"{dev1}:{port1} {ip1_part}"
                    else:
                        ip1_display = f"{dev1}:{port1}"
                        
                    if ip2:
                        # Remove leading newlines and format properly
                        ip2_clean = ip2.lstrip("\n")
                        # Extract the IP part correctly
                        if ":" in ip2_clean:
                            # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                            ip2_part = ip2_clean.split(":")[-1]
                        else:
                            ip2_part = ip2_clean
                        ip2_display = f"{dev2}:{port2} {ip2_part}"
                    else:
                        ip2_display = f"{dev2}:{port2}"
                    
                    connection_lines.append(f"{connection_index:3d}. {ip1_display} <-> {ip2_display}")
                    connection_index += 1
            else:
                # Multiple connections (AE interfaces)
                for conn in connections:
                    dev1, port1, dev2, port2 = conn
                    connection_lines.append(f"{connection_index:3d}. {dev1}:{port1} <-> {dev2}:{port2}")
                    connection_index += 1
                
                # Print AE interface information if IPv4 option is enabled
                if self.args.ipv4:
                    device1 = topology.devices[dev1]
                    device2 = topology.devices[dev2]
                    
                    # Get AE interfaces for all connections in this group
                    ae_interfaces1 = []
                    ae_interfaces2 = []
                    ips1 = []
                    ips2 = []
                    
                    for conn in connections:
                        d1, p1, d2, p2 = conn
                        ae1 = device1.interface_ae.get(p1, "")
                        ae2 = device2.interface_ae.get(p2, "")
                        ip1 = device1.interfaces.get(p1, "")
                        ip2 = device2.interfaces.get(p2, "")
                        
                        if ae1 and ae1 not in ae_interfaces1:
                            ae_interfaces1.append(ae1)
                        if ae2 and ae2 not in ae_interfaces2:
                            ae_interfaces2.append(ae2)
                        if ip1:
                            ips1.append((p1, ip1))
                        if ip2:
                            ips2.append((p2, ip2))
                    
                    # Find common AE interface if exists
                    common_ae1 = ae_interfaces1[0] if len(set(ae_interfaces1)) == 1 else ""
                    common_ae2 = ae_interfaces2[0] if len(set(ae_interfaces2)) == 1 else ""
                    
                    if common_ae1 and common_ae2:
                        # Get AE interface IPs
                        ae_ip1 = device1.interfaces.get(common_ae1, "")
                        ae_ip2 = device2.interfaces.get(common_ae2, "")
                        
                        # Format interface list
                        ports1 = ",".join([conn[1] for conn in connections])
                        ports2 = ",".join([conn[3] for conn in connections])
                        
                        # Format AE interface with IP
                        if ae_ip1:
                            # Extract just the IP part (after the last colon)
                            ae_ip1_clean = ae_ip1.lstrip("\n")
                            if ":" in ae_ip1_clean:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ae_ip1_part = ae_ip1_clean.split(":")[-1]
                            else:
                                ae_ip1_part = ae_ip1_clean
                            ae_display1 = f"{ports1}:{common_ae1} {ae_ip1_part}"
                        else:
                            ae_display1 = f"{ports1}:{common_ae1}"
                            
                        if ae_ip2:
                            # Extract just the IP part (after the last colon)
                            ae_ip2_clean = ae_ip2.lstrip("\n")
                            if ":" in ae_ip2_clean:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ae_ip2_part = ae_ip2_clean.split(":")[-1]
                            else:
                                ae_ip2_part = ae_ip2_clean
                            ae_display2 = f"{ports2}:{common_ae2} {ae_ip2_part}"
                        else:
                            ae_display2 = f"{ports2}:{common_ae2}"
                        
                        connection_lines.append(f"    {ae_display1} <-> {ae_display2}")
        
        # Create single text box for all connection IP information
        if len(connection_lines) > 2:  # Only create if there's actual connection info (title + empty line + content)
            # Calculate text box size based on content with precise auto-scaling
            max_line_length = max(len(line) for line in connection_lines)
            # More precise width calculation: 5.5 pixels per character + 15px padding (reduced from 30)
            text_width = max(180, int(max_line_length * 5.5 + 15))
            # More precise height calculation: 14px per line + 25px padding (reduced from 40)
            text_height = max(70, len(connection_lines) * 14 + 25)
            
            element_id = str(self.next_id)
            self.next_id += 1
            
            # Create content with HTML line breaks for DrawIO
            connection_text = "<br>".join(connection_lines)
            escaped_connection_text = self._escape_xml(connection_text)
            
            # Create element with light blue background for connection IP info
            element = f'''<mxCell id="{element_id}" value="{escaped_connection_text}" style="text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;rounded=0;fontSize=10;fontColor=#000000;fillColor=#bbdefb;strokeColor=#000000;" vertex="1" parent="1">
                <mxGeometry x="50" y="{diagram_bottom_y}" width="{text_width}" height="{text_height}" as="geometry"/>
              </mxCell>'''
            
            # Check for collisions before adding
            bbox = {'x': 50, 'y': diagram_bottom_y, 'w': text_width, 'h': text_height}
            if not spatial_index.overlaps(bbox):
                ip_elements.append(element)
                spatial_index.insert(bbox, element_id)
                diagram_bottom_y += text_height + 15  # Move down for next element
        
        # Process interface IP information for IPv4 option
        interface_lines = ["Interface IP info", ""]  # Add empty line after title
        sorted_devices = sorted(topology.devices.items())
        
        if self.args.ipv4:
            # Collect interface IP information for all devices
            for device_name, device in sorted_devices:
                device_lines = [f"{device_name}:"]
                
                # Add router ID if available
                if device.router_id:
                    device_lines.append(f"  lo0.0: {device.router_id}/32")
                
                # Add interface IPs
                for interface_name, ip_info in device.interfaces.items():
                    if ip_info and interface_name != "lo0":
                        # Check if this interface has neighbors
                        has_neighbor = False
                        for local_port, remote_device, remote_port in device.neighbors:
                            if local_port == interface_name:
                                has_neighbor = True
                                break
                        
                        # For routers, only print interfaces with neighbors
                        # For switches, print all interfaces
                        if device.device_type == 'switch' or has_neighbor:
                            # Get AE interface if exists
                            ae_interface = device.interface_ae.get(interface_name, "")
                            # Clean up IP info - remove leading newlines
                            clean_ip_info = ip_info.lstrip("\n")
                            
                            # Extract just the IP part (after the last colon)
                            if ":" in clean_ip_info:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ip_part = clean_ip_info.split(":")[-1]
                            else:
                                ip_part = clean_ip_info
                            
                            # Handle IRB interfaces specially to show full info including ARP
                            if interface_name.startswith("irb0."):
                                # For IRB interfaces, split by newlines to show each IP on a separate line
                                ip_lines = clean_ip_info.split("\n")
                                for i, ip_line in enumerate(ip_lines):
                                    if i == 0:
                                        device_lines.append(f"  {interface_name}: {ip_line}")
                                    else:
                                        device_lines.append(f"    {ip_line}")
                            else:
                                if ae_interface:
                                    device_lines.append(f"  {interface_name},{ae_interface}: {ip_part}")
                                else:
                                    device_lines.append(f"  {interface_name}: {ip_part}")
                
                if len(device_lines) > 1:  # Only add device if it has interface info
                    interface_lines.extend(device_lines)
                    interface_lines.append("")  # Empty line between devices
            
            # Remove trailing empty line if exists
            if interface_lines and interface_lines[-1] == "":
                interface_lines.pop()
            
            # Create single text box for all device interface IP information
            if len(interface_lines) > 2:  # Only create if there's actual interface info (title + empty line + content)
                # Calculate text box size based on content with precise auto-scaling
                max_line_length = max(len(line) for line in interface_lines)
                # More precise width calculation: 5.5 pixels per character + 15px padding (reduced from 30)
                text_width = max(180, int(max_line_length * 5.5 + 15))
                # More precise height calculation: 14px per line + 25px padding (reduced from 40)
                text_height = max(70, len(interface_lines) * 14 + 25)
                
                element_id = str(self.next_id)
                self.next_id += 1
                
                # Create content with HTML line breaks for DrawIO
                interface_text = "<br>".join(interface_lines)
                escaped_interface_text = self._escape_xml(interface_text)
                
                # Create element with light yellow background for interface IP info (different from link IP info)
                element = f'''<mxCell id="{element_id}" value="{escaped_interface_text}" style="text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;rounded=0;fontSize=10;fontColor=#000000;fillColor=#fff9c4;strokeColor=#000000;" vertex="1" parent="1">
                    <mxGeometry x="50" y="{diagram_bottom_y}" width="{text_width}" height="{text_height}" as="geometry"/>
                  </mxCell>'''
                
                # Check for collisions before adding
                bbox = {'x': 50, 'y': diagram_bottom_y, 'w': text_width, 'h': text_height}
                if not spatial_index.overlaps(bbox):
                    ip_elements.append(element)
                    spatial_index.insert(bbox, element_id)
                    diagram_bottom_y += text_height + 15  # Move down for next element
        
        # Process Layer 2 information for Layer 2 option
        layer2_lines = ["Layer 2 Interface Information", ""]  # Add empty line after title
        
        if self.args.layer2:
            # Collect Layer 2 information for all devices
            for device_name, device in sorted_devices:
                device_lines = [f"{device_name}:"]
                
                # Add trunk interface information with correct format
                for interface_name, vlan_members in device.trunk_interfaces.items():
                    if vlan_members == "all":
                        device_lines.append(f"  {interface_name} trunk: all VLANs")
                    else:
                        # Format VLAN members list with correct brackets format
                        if isinstance(vlan_members, list):
                            # For each VLAN, try to find the VLAN ID from the vlan_irb_mapping
                            formatted_vlans = []
                            for vlan_name in vlan_members:
                                if vlan_name in device.vlan_irb_mapping:
                                    # Get the VLAN ID from the mapping
                                    _, vlan_id = device.vlan_irb_mapping[vlan_name]
                                    formatted_vlans.append(f"{vlan_name}<{vlan_id}>")
                                else:
                                    # If VLAN ID not found, just use the VLAN name
                                    formatted_vlans.append(vlan_name)
                            vlan_str = " ".join(formatted_vlans)
                            device_lines.append(f"  {interface_name} trunk [ {vlan_str} ]")
                        else:
                            # Single VLAN
                            if vlan_members in device.vlan_irb_mapping:
                                # Get the VLAN ID from the mapping
                                _, vlan_id = device.vlan_irb_mapping[vlan_members]
                                device_lines.append(f"  {interface_name} trunk [ {vlan_members}<{vlan_id}> ]")
                            else:
                                # If VLAN ID not found, just use the VLAN name
                                device_lines.append(f"  {interface_name} trunk [ {vlan_members} ]")
                
                # Print access interface information (interfaces that are not trunk)
                # For switches, we can infer access interfaces as those that have VLAN information
                # but are not explicitly marked as trunk
                for interface_name, ip_info in device.interfaces.items():
                    # Skip loopback and IRB interfaces
                    if interface_name in ["lo0"] or interface_name.startswith("irb"):
                        continue
                    
                    # Skip interfaces that are already marked as trunk
                    if interface_name in device.trunk_interfaces:
                        continue
                    
                    # Check if this is an access interface with VLAN information
                    if hasattr(device, 'access_interfaces') and interface_name in device.access_interfaces:
                        vlan_name = device.access_interfaces[interface_name]
                        # Try to find the VLAN ID from the vlan_irb_mapping
                        if vlan_name in device.vlan_irb_mapping:
                            # Get the VLAN ID from the mapping
                            _, vlan_id = device.vlan_irb_mapping[vlan_name]
                            print(f"  {interface_name} access {vlan_name}:{vlan_id}")
                        else:
                            # If VLAN ID not found, just use the VLAN name
                            print(f"  {interface_name} access {vlan_name}")
                    else:
                        # Check if this is an access interface by looking for VLAN information
                        # Access interfaces typically have a single VLAN associated with them
                        # In Junos, access interfaces have "interface-mode access" and a single VLAN
                        # For now, we'll just note that these are access interfaces without specific VLAN info
                        # unless we can extract it from the configuration
                        
                        # For access interfaces, we can check if they're connected to other devices
                        # and mark them as access interfaces
                        has_neighbor = False
                        for local_port, remote_device, remote_port in device.neighbors:
                            if local_port == interface_name:
                                has_neighbor = True
                                break
                        
                        # For switches, if an interface is not trunk and has a neighbor, it's likely an access interface
                        if device.device_type == 'switch' and has_neighbor and interface_name not in device.trunk_interfaces:
                            print(f"  {interface_name} access: connected to neighbor")
                
                if len(device_lines) > 1:  # Only add device if it has Layer 2 info
                    layer2_lines.extend(device_lines)
                    layer2_lines.append("")  # Empty line between devices
            
            # Remove trailing empty line if exists
            if layer2_lines and layer2_lines[-1] == "":
                layer2_lines.pop()
            
            # Create single text box for all Layer 2 interface information
            if len(layer2_lines) > 2:  # Only create if there's actual Layer 2 info (title + empty line + content)
                # Calculate text box size based on content with precise auto-scaling
                max_line_length = max(len(line) for line in layer2_lines)
                # More precise width calculation: 5.5 pixels per character + 15px padding
                text_width = max(180, int(max_line_length * 5.5 + 15))
                # More precise height calculation: 14px per line + 25px padding
                text_height = max(70, len(layer2_lines) * 14 + 25)
                
                element_id = str(self.next_id)
                self.next_id += 1
                
                # Create content with HTML line breaks for DrawIO
                layer2_text = "<br>".join(layer2_lines)
                escaped_layer2_text = self._escape_xml(layer2_text)
                
                # Create element with light green background for Layer 2 info
                element = f'''<mxCell id="{element_id}" value="{escaped_layer2_text}" style="text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;rounded=0;fontSize=10;fontColor=#000000;fillColor=#e8f5e8;strokeColor=#000000;" vertex="1" parent="1">
                    <mxGeometry x="50" y="{diagram_bottom_y}" width="{text_width}" height="{text_height}" as="geometry"/>
                  </mxCell>'''
                
                # Check for collisions before adding
                bbox = {'x': 50, 'y': diagram_bottom_y, 'w': text_width, 'h': text_height}
                if not spatial_index.overlaps(bbox):
                    ip_elements.append(element)
                    spatial_index.insert(bbox, element_id)
        
        return ip_elements
    
    def _escape_xml_for_html(self, text: str) -> str:
        """Escape special characters for XML attributes while preserving HTML tags"""
        # First escape XML special characters
        escaped = text.replace('&', '&amp;') \
                     .replace('<', '&lt;') \
                     .replace('>', '&gt;') \
                     .replace('"', '&quot;') \
                     .replace("'", '&apos;')
        
        # Then unescape HTML line breaks so they work in DrawIO
        escaped = escaped.replace('&lt;br&gt;', '<br>')
        
        return escaped
    
    def generate_drawio_xml(self, topology: TopologyBuilder) -> str:
        """Generate complete DrawIO XML with simplified label positioning"""
        # Calculate layout
        topology.calculate_layout()
        
        # Reset ID counter to ensure clean start
        self.next_id = 2
        self.device_id_map.clear()
        
        # Store topology reference for accessing device information
        self.topology = topology
        
        # Register device positions for label placement
        for device_name, device in topology.devices.items():
            x, y = device.position
            # Calculate device center (device size is 80x60)
            center = (x + 40, y + 30)
            self.register_device_position(device_name, center)
        
        # First pass: Create all device IDs to ensure they exist
        for device_name in topology.devices.keys():
            self.get_device_id(device_name)
        
        # Generate device shapes
        shapes = []
        for device in topology.devices.values():
            shapes.append(self.create_device_shape(device))
        
        # Generate connection lines with simplified label positioning
        lines = []
        
        # Group connections by device pairs to handle multiple connections properly
        device_pair_connections = defaultdict(list)
        for dev1, port1, dev2, port2 in topology.connections:
            # Create consistent device pair key (alphabetically sorted)
            device_pair = tuple(sorted([dev1, dev2]))
            device_pair_connections[device_pair].append((dev1, port1, dev2, port2))
        
        # Generate connections with simplified label positioning
        for device_pair, connections in device_pair_connections.items():
            total_connections = len(connections)
            
            if total_connections > 1:
                # For multiple connections, create separate lines with simplified positioning
                for connection_index, (dev1, port1, dev2, port2) in enumerate(connections):
                    lines.append(self.create_connection_line(dev1, port1, dev2, port2, 
                                                             connection_index, total_connections))
            else:
                # Single connection with simplified positioning
                dev1, port1, dev2, port2 = connections[0]
                lines.append(self.create_connection_line(dev1, port1, dev2, port2, 0, 1))
        
        # Generate IP information elements if IPv4 option is enabled
        ip_elements = []
        if self.args and (self.args.ipv4 or self.args.layer2):
            ip_elements = self._create_ip_info_elements(topology)
        
        # Complete XML structure with proper formatting
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="Electron" modified="2024-01-01T00:00:00.000Z" agent="5.0" version="22.1.16" etag="topology" type="device">
  <diagram name="Network Topology" id="topology">
    <mxGraphModel dx="1422" dy="758" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="827" pageHeight="1169" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
        {''.join(shapes)}
        {''.join(lines)}
        {''.join(ip_elements)}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>'''
        
        return xml_content
    
    def get_device_id(self, device_name: str) -> str:
        """Get or create unique ID for device"""
        if device_name not in self.device_id_map:
            self.device_id_map[device_name] = str(self.next_id)
            self.next_id += 1
        return self.device_id_map[device_name]
    
    def create_device_shape(self, device: DeviceInfo) -> str:
        """Create XML for device shape"""
        device_id = self.get_device_id(device.name)
        x, y = device.position
        
        # Use display name for cleaner appearance
        display_name = getattr(device, 'display_name', device.name)
        
        # Build the device label content with proper XML escaping
        label_lines = []
        
        # Escape display name and add as first line
        label_lines.append(self._escape_xml(display_name))
        
        # Add router-id if available
        if device.router_id:
            label_lines.append(self._escape_xml(device.router_id))
        
        # Join lines with HTML line breaks for proper line breaks
        label_content = "&lt;br&gt;".join(label_lines)
        
        # Choose shape and color based on device type
        if device.device_type == 'router':
            shape = 'ellipse;html=1'
            fillColor = '#dae8fc'
            strokeColor = '#6c8ebf'
        elif device.device_type == 'switch':
            shape = 'rounded=1;whiteSpace=wrap;html=1'
            fillColor = '#d5e8d4'
            strokeColor = '#82b366'
        else:
            shape = 'whiteSpace=wrap;html=1'
            fillColor = '#fff2cc'
            strokeColor = '#d6b656'
    
        width = 80
        height = 60 + (len(label_lines) - 1) * 15  # Increase height for additional lines
    
        # Use smaller font size for hostname to make room for router ID
        device_xml = f'''<mxCell id="{device_id}" value="{label_content}" style="{shape};fillColor={fillColor};strokeColor={strokeColor};fontStyle=1;fontSize=10;whiteSpace=wrap;html=1;align=center;" vertex="1" parent="1">
            <mxGeometry x="{x}" y="{y}" width="{width}" height="{height}" as="geometry"/>
          </mxCell>'''
        
        return device_xml

    def _escape_xml(self, text: str) -> str:
        """Escape special characters for XML"""
        return text.replace('&', '&amp;') \
                   .replace('<', '&lt;') \
                   .replace('>', '&gt;') \
                   .replace('"', '&quot;') \
                   .replace("'", '&apos;')
    
    def _create_interface_elements(self, device: DeviceInfo, x: int, y: int, width: int, height: int) -> str:
        """Create separate interface elements outside the device shape"""
        interface_xml = ""
        
        # For routers, don't display interfaces without connections
        # For switches, display access interfaces below the device shape
        if device.device_type == 'router':
            # For routers, we don't display interfaces without connections, so return empty
            return ""
        elif device.device_type == 'switch':
            # For switches, display access interfaces below the device shape
            interface_y_offset = height + 10  # Position below the device
            interface_x_offset = 0
            
            for interface_name, ip_address in device.interfaces.items():
                # Check if this interface has neighbors
                has_neighbor = False
                for local_port, remote_device, remote_port in device.neighbors:
                    if local_port == interface_name:
                        has_neighbor = True
                        break
                
                # For switches, if no neighbor, display it
                if not has_neighbor:
                    interface_content = interface_name
                        
                    # Create interface element
                    interface_id = str(self.next_id)
                    self.next_id += 1
                    
                    # Escape content for XML
                    escaped_content = self._escape_xml(interface_content)
                    
                    interface_xml += f'''<mxCell id="{interface_id}" value="{escaped_content}" style="text;html=1;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=9;fontColor=#666666;" vertex="1" parent="1">
                        <mxGeometry x="{x + interface_x_offset}" y="{y + interface_y_offset}" width="80" height="30" as="geometry"/>
                      </mxCell>'''
                    
                    # Update position for next interface
                    interface_y_offset += 35  # Move down for next interface
        
        return interface_xml
    
    def get_interface_speed_color(self, interface_name: str) -> str:
        """Determine interface speed color based on interface name patterns
        
        Speed mapping:
        1G - black (#000000)
        10G - red (#ff0000) 
        40G - blue (#0066cc)
        100G - yellow (#ffcc00)
        400G - green (#00cc00)
        """
        interface_lower = interface_name.lower()
        
        # 400G interfaces - highest priority
        if any(pattern in interface_lower for pattern in ['et-0/3', 'et-0/4', 'cd-', '400g']) or \
           (interface_lower.startswith('et-') and ('/3' in interface_lower or '/4' in interface_lower)):
            return '#00cc00'  # green for 400G
        
        # 100G interfaces  
        if any(pattern in interface_lower for pattern in ['et-0/0', 'et-0/1', 'et-0/2', 'ce-', '100g']):
            return '#ffcc00'  # yellow for 100G
        
        # 40G interfaces
        if 'xe-' in interface_lower:
            return '#0066cc'  # blue for 40G
        
        # 10G interfaces (ge- high-speed interfaces)
        if any(pattern in interface_lower for pattern in ['ge-0/0/4', 'ge-0/0/5', '10g']):
            return '#ff0000'  # red for 10G
        
        # 1G interfaces (default for most ge-, fe-, etc.)
        if any(pattern in interface_lower for pattern in ['ge-', 'fe-', 'gi', 'fa', '1g']):
            return '#000000'  # black for 1G
        
        # Default to black for unknown interfaces
        return '#000000'


def main():
    """Main function to generate network topology diagram"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Select directory
    selected_dir = select_directory()
    
    # Validate required files
    if not validate_required_files(selected_dir):
        sys.exit(1)
    
    # Create topology builder
    topology_builder = TopologyBuilder(
        str(selected_dir / "config"),
        str(selected_dir / "lldp")
    )
    
    # Build topology
    topology_builder.build_topology()
    
    # Create DrawIO generator and pass args for IPv4 option
    drawio_generator = DrawIOGenerator(args)
    
    # Generate DrawIO XML
    xml_content = drawio_generator.generate_drawio_xml(topology_builder)
    
    # Write to file with proper formatting to avoid line wrapping
    output_file = f"{selected_dir.name}-topo.drawio"
    try:
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            # Write XML content without line wrapping issues
            f.write(xml_content)
        
        # Print the requested information
        print(f"Configuration directory: {selected_dir.name}/config")
        print(f"LLDP directory: {selected_dir.name}/lldp")
        print(f"Output file: {output_file}")
        print("\nTopology diagram generated successfully!")
        print(f"Output file: {os.path.abspath(output_file)}")
        print("Open with: Draw.io (https://app.diagrams.net/)")
        
        # Print topology summary
        print("\nTopology Summary:")
        print(f"  Devices: {len(topology_builder.devices)}")
        print(f"  Connections: {len(topology_builder.connections)}")
        
        # Count connections per device correctly
        connection_count = defaultdict(int)
        for dev1, port1, dev2, port2 in topology_builder.connections:
            connection_count[dev1] += 1
            connection_count[dev2] += 1
        
        # Sort devices by connection count (descending) then alphabetically
        sorted_devices = sorted(topology_builder.devices.items(), 
                               key=lambda x: (-connection_count[x[0]], x[0]))
        
        print("\n")
        for device_name, device in sorted_devices:
            count = connection_count[device_name]
            device_type = device.device_type
            print(f"  • {device_name} ({device_type}): {count} connections")
        
        # Print detailed connection information
        print("\n\nDetailed Connection Information:")
        # Sort connections with smaller hostname first in each connection
        sorted_connections = []
        for dev1, port1, dev2, port2 in topology_builder.connections:
            # Ensure smaller hostname is first
            if dev1 <= dev2:
                sorted_connections.append((dev1, port1, dev2, port2))
            else:
                sorted_connections.append((dev2, port2, dev1, port1))
        # Sort the connections
        sorted_connections.sort()
        
        # Group connections by device pairs for AE interface handling
        connection_groups = defaultdict(list)
        for dev1, port1, dev2, port2 in sorted_connections:
            device_pair = tuple(sorted([dev1, dev2]))
            connection_groups[device_pair].append((dev1, port1, dev2, port2))
        
        connection_index = 1
        for device_pair, connections in connection_groups.items():
            dev1, port1, dev2, port2 = connections[0]
            if len(connections) == 1:
                # Single connection
                device1 = topology_builder.devices[dev1]
                device2 = topology_builder.devices[dev2]
                ip1 = device1.interfaces.get(port1, "")
                ip2 = device2.interfaces.get(port2, "")
                
                if ip1 or ip2:
                    # Format interface list with hostnames
                    if ip1:
                        # Remove leading newlines and format properly
                        ip1_clean = ip1.lstrip("\n")
                        # Extract the IP part correctly
                        if ":" in ip1_clean:
                            # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                            ip1_part = ip1_clean.split(":")[-1]
                        else:
                            ip1_part = ip1_clean
                        ip1_display = f"{dev1}:{port1} {ip1_part}"
                    else:
                        ip1_display = f"{dev1}:{port1}"
                        
                    if ip2:
                        # Remove leading newlines and format properly
                        ip2_clean = ip2.lstrip("\n")
                        # Extract the IP part correctly
                        if ":" in ip2_clean:
                            # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                            ip2_part = ip2_clean.split(":")[-1]
                        else:
                            ip2_part = ip2_clean
                        ip2_display = f"{dev2}:{port2} {ip2_part}"
                    else:
                        ip2_display = f"{dev2}:{port2}"
                        
                    # This line was incorrectly referencing connection_lines, removed
                connection_index += 1
            else:
                # Multiple connections (AE interfaces)
                for conn in connections:
                    dev1, port1, dev2, port2 = conn
                    print(f"{connection_index:3d}. {dev1}:{port1} <-> {dev2}:{port2}")
                    connection_index += 1
                
                # Print AE interface information if IPv4 option is enabled
                if args.ipv4:
                    device1 = topology_builder.devices[dev1]
                    device2 = topology_builder.devices[dev2]
                    
                    # Get AE interfaces for all connections in this group
                    ae_interfaces1 = []
                    ae_interfaces2 = []
                    ips1 = []
                    ips2 = []
                    
                    for conn in connections:
                        d1, p1, d2, p2 = conn
                        ae1 = device1.interface_ae.get(p1, "")
                        ae2 = device2.interface_ae.get(p2, "")
                        ip1 = device1.interfaces.get(p1, "")
                        ip2 = device2.interfaces.get(p2, "")
                        
                        if ae1 and ae1 not in ae_interfaces1:
                            ae_interfaces1.append(ae1)
                        if ae2 and ae2 not in ae_interfaces2:
                            ae_interfaces2.append(ae2)
                        if ip1:
                            ips1.append((p1, ip1))
                        if ip2:
                            ips2.append((p2, ip2))
                    
                    # Find common AE interface if exists
                    common_ae1 = ae_interfaces1[0] if len(set(ae_interfaces1)) == 1 else ""
                    common_ae2 = ae_interfaces2[0] if len(set(ae_interfaces2)) == 1 else ""
                    
                    if common_ae1 and common_ae2:
                        # Get AE interface IPs
                        ae_ip1 = device1.interfaces.get(common_ae1, "")
                        ae_ip2 = device2.interfaces.get(common_ae2, "")
                        
                        # Format interface list
                        ports1 = ",".join([conn[1] for conn in connections])
                        ports2 = ",".join([conn[3] for conn in connections])
                        
                        # Format AE interface with IP
                        if ae_ip1:
                            # Extract just the IP part (after the last colon)
                            ae_ip1_clean = ae_ip1.lstrip("\n")
                            if ":" in ae_ip1_clean:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ae_ip1_part = ae_ip1_clean.split(":")[-1]
                            else:
                                ae_ip1_part = ae_ip1_clean
                            ae_display1 = f"{ports1}:{common_ae1} {ae_ip1_part}"
                        else:
                            ae_display1 = f"{ports1}:{common_ae1}"
                            
                        if ae_ip2:
                            # Extract just the IP part (after the last colon)
                            ae_ip2_clean = ae_ip2.lstrip("\n")
                            if ":" in ae_ip2_clean:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ae_ip2_part = ae_ip2_clean.split(":")[-1]
                            else:
                                ae_ip2_part = ae_ip2_clean
                            ae_display2 = f"{ports2}:{common_ae2} {ae_ip2_part}"
                        else:
                            ae_display2 = f"{ports2}:{common_ae2}"
                        
                        print(f"{ae_display1} <-> {ae_display2}")
        
        # Collect all connection IP information
        connection_lines = ["link IP Info", ""]  # Add empty line after title



        
        # Print additional interface information if IPv4 option is enabled
        if args.ipv4:
            print("\n\nInterface IP info:")
            for device_name, device in sorted_devices:
                print(f"{device_name}:")
                # Print router ID if available
                if device.router_id:
                    print(f"  lo0.0: {device.router_id}/32")
                
                # Print interface IPs
                for interface_name, ip_info in device.interfaces.items():
                    if ip_info and interface_name != "lo0":
                        # Check if this interface has neighbors
                        has_neighbor = False
                        for local_port, remote_device, remote_port in device.neighbors:
                            if local_port == interface_name:
                                has_neighbor = True
                                break
                        
                        # For routers, only print interfaces with neighbors
                        # For switches, print all interfaces
                        if device.device_type == 'switch' or has_neighbor:
                            # Get AE interface if exists
                            ae_interface = device.interface_ae.get(interface_name, "")
                            # Clean up IP info - remove leading newlines
                            clean_ip_info = ip_info.lstrip("\n")
                            
                            # Extract just the IP part (after the last colon)
                            if ":" in clean_ip_info:
                                # For formats like ".0:10.0.16.2/30" or ":10.0.13.1/30"
                                ip_part = clean_ip_info.split(":")[-1]
                            else:
                                ip_part = clean_ip_info
                            
                            if ae_interface:
                                print(f"  {interface_name},{ae_interface}: {ip_part}")
                            else:
                                # Handle IRB interfaces specially
                                if interface_name.startswith("irb0."):
                                    # For IRB interfaces, we want to show the full info
                                    # Split by newlines to show each IP on a separate line
                                    ip_lines = clean_ip_info.split("\n")
                                    for i, ip_line in enumerate(ip_lines):
                                        if i == 0:
                                            print(f"  {interface_name}: {ip_line}")
                                        else:
                                            print(f"    {ip_line}")
                                else:
                                    print(f"  {interface_name}: {ip_part}")
                print()  # Empty line between devices
            

        
        # Print Layer 2 information if Layer 2 option is enabled
        if args.layer2:
            print("\n\nLayer 2 Interface Information:")
            for device_name, device in sorted_devices:
                print(f"{device_name}:")
                # Print trunk interface information with correct format
                for interface_name, vlan_members in device.trunk_interfaces.items():
                    if vlan_members == "all":
                        print(f"  {interface_name} trunk: all VLANs")
                    else:
                        # Format VLAN members list with correct brackets format
                        if isinstance(vlan_members, list):
                            # For each VLAN, try to find the VLAN ID from the vlan_irb_mapping
                            formatted_vlans = []
                            for vlan_name in vlan_members:
                                if vlan_name in device.vlan_irb_mapping:
                                    # Get the VLAN ID from the mapping
                                    _, vlan_id = device.vlan_irb_mapping[vlan_name]
                                    formatted_vlans.append(f"{vlan_name}<{vlan_id}>")
                                else:
                                    # If VLAN ID not found, just use the VLAN name
                                    formatted_vlans.append(vlan_name)
                            vlan_str = " ".join(formatted_vlans)
                            print(f"  {interface_name} trunk [ {vlan_str} ]")
                        else:
                            # Single VLAN
                            if vlan_members in device.vlan_irb_mapping:
                                # Get the VLAN ID from the mapping
                                _, vlan_id = device.vlan_irb_mapping[vlan_members]
                                print(f"  {interface_name} trunk [ {vlan_members}<{vlan_id}> ]")
                            else:
                                # If VLAN ID not found, just use the VLAN name
                                print(f"  {interface_name} trunk [ {vlan_members} ]")
                print()  # Empty line between devices
            
    except Exception as e:
        print(f"Error writing to file {output_file}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()