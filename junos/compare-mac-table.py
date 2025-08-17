#!/usr/bin/env python3
import os
import re
import datetime
import sys
from collections import defaultdict

def parse_mac_table(filename):
    """
    Parse MAC table file in the specific format provided
    """
    mac_entries = []
    
    try:
        with open(filename, 'r') as f:
            content = f.readlines()
        
        # Pattern for the specific MAC table format:
        # Vlan name  MAC address      flags  Age  Logical interface  NH Index  RTR ID
        # v1001      00:10:94:00:00:01 D      -    ae1.0              0         0
        mac_pattern = re.compile(
            r'^\s*(\S+)\s+'           # Vlan name (group 1)
            r'([0-9a-fA-F:]{17})\s+'  # MAC address (group 2)
            r'([A-Z])\s+'             # MAC flags (group 3)
            r'(\S+)\s+'               # Age (group 4)
            r'(\S+)\s+'               # Logical interface (group 5)
            r'(\d+)\s+'               # NH Index (group 6)
            r'(\d+)'                  # RTR ID (group 7)
        )
        
        for line in content:
            line = line.strip()
            
            # Skip header lines and empty lines
            if (not line or 
                line.startswith(('Vlan', 'name', '----', '====')) or
                'Total' in line or
                'entries' in line):
                continue
            
            match = mac_pattern.match(line)
            if match:
                vlan, mac, flags, age, interface, nh_index, rtr_id = match.groups()
                
                entry = {
                    'vlan': vlan,
                    'flags': flags,
                    'age': age,
                    'interface': interface,
                    'nh_index': nh_index,
                    'rtr_id': rtr_id,
                    'line': line,
                    'mac': mac
                }
                mac_entries.append(entry)
        
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
    except PermissionError:
        print(f"Error: Permission denied when reading {filename}")
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        import traceback
        traceback.print_exc()
    
    return mac_entries

def extract_timestamp_from_filename(filename):
    """
    Extract timestamp from filename format: hostname-YYYYMMDD-HHMMSS.txt
    """
    basename = os.path.basename(filename)
    parts = basename.split('-')
    if len(parts) >= 3:
        # Assuming format: hostname-YYYYMMDD-HHMMSS.txt
        timestamp_str = parts[-2] + parts[-1].replace('.txt', '')  # YYYYMMDDHHMMSS
        try:
            # Try to parse as datetime
            return datetime.datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
        except ValueError:
            pass
    return None

def is_main_difference(diff):
    """Check if a difference line is a main difference (not a grouped item)"""
    stripped_diff = diff.strip()
    return (stripped_diff and 
            not diff.startswith(('  ', 'Other MACs', '- MAC', 'Other')))

def group_entries_by_mac_interface(mac_table):
    """Group entries by MAC address and interface"""
    grouped = defaultdict(list)
    for entry in mac_table:
        key = (entry['mac'], entry['interface'])
        grouped[key].append(entry)
    return grouped

def group_entries_by_mac_only(mac_table):
    """Group entries by MAC address only (to detect moves)"""
    grouped = defaultdict(set)
    for entry in mac_table:
        grouped[entry['mac']].add((entry['interface'], entry['vlan'], entry['line']))
    return grouped

def detect_mac_moves(all_macs, baseline_macs, new_macs, baseline_grouped, new_grouped, 
                    moves_list, mac_moves, baseline_name, new_name):
    """Detect and record MAC moves between interfaces"""
    processed_macs = set()
    
    for mac in all_macs:
        baseline_interfaces = {iface for iface, vlan, line in baseline_macs.get(mac, set())}
        new_interfaces = {iface for iface, vlan, line in new_macs.get(mac, set())}
        
        # Check if MAC moved between interfaces
        if mac in baseline_macs and mac in new_macs and baseline_interfaces != new_interfaces:
            moved_to = new_interfaces - baseline_interfaces
            moved_from = baseline_interfaces - new_interfaces
            
            if moved_to and moved_from:
                # MAC moved from some interfaces to others
                for from_interface in moved_from:
                    for to_interface in moved_to:
                        # Check if VLANs also changed
                        baseline_vlans = {vlan for iface, vlan, line in baseline_macs.get(mac, set()) if iface == from_interface}
                        new_vlans = {vlan for iface, vlan, line in new_macs.get(mac, set()) if iface == to_interface}
                        
                        move_info = {
                            'mac': mac,
                            'from_interface': from_interface,
                            'to_interface': to_interface,
                            'from_vlans': baseline_vlans,
                            'to_vlans': new_vlans
                        }
                        mac_moves.append(move_info)
                        
                        # Store move details for grouping
                        baseline_entries = [entry for (m, iface), entries in baseline_grouped.items() 
                                          if m == mac and iface == from_interface for entry in entries]
                        new_entries = [entry for (m, iface), entries in new_grouped.items() 
                                     if m == mac and iface == to_interface for entry in entries]
                        
                        moves_list.append({
                            'mac': mac,
                            'from_interface': from_interface,
                            'to_interface': to_interface,
                            'from_vlans': baseline_vlans,
                            'to_vlans': new_vlans,
                            'baseline_entries': baseline_entries,
                            'new_entries': new_entries,
                            'baseline_name': baseline_name,
                            'new_name': new_name
                        })
                processed_macs.add(mac)
    
    return processed_macs

def check_vlan_changes(all_macs, processed_macs, mac_table_baseline, mac_table_new,
                      baseline_grouped, new_grouped, baseline_macs, new_macs,
                      vlan_changes, new_entries_list, missing_entries_list,
                      baseline_name, new_name):
    """Check for VLAN changes and new/missing entries"""
    for mac in all_macs:
        if mac in processed_macs:
            continue
            
        # Get all interface-vlan combinations for this MAC in both files
        baseline_entries_for_mac = [entry for entry in mac_table_baseline if entry['mac'] == mac]
        new_entries_for_mac = [entry for entry in mac_table_new if entry['mac'] == mac]
        
        # Group by interface
        baseline_interfaces_for_mac = defaultdict(list)
        new_interfaces_for_mac = defaultdict(list)
        
        for entry in baseline_entries_for_mac:
            baseline_interfaces_for_mac[entry['interface']].append(entry)
        for entry in new_entries_for_mac:
            new_interfaces_for_mac[entry['interface']].append(entry)
        
        # Check each interface this MAC is on
        all_interfaces = set(baseline_interfaces_for_mac.keys()) | set(new_interfaces_for_mac.keys())
        for interface in all_interfaces:
            baseline_vlan_set = {entry['vlan'] for entry in baseline_interfaces_for_mac.get(interface, [])}
            new_vlan_set = {entry['vlan'] for entry in new_interfaces_for_mac.get(interface, [])}
            
            if baseline_vlan_set != new_vlan_set:
                if not baseline_vlan_set:
                    # New on this interface
                    for entry in new_interfaces_for_mac[interface]:
                        new_entries_list.append({
                            'mac': mac,
                            'interface': interface,
                            'vlan': entry['vlan'],
                            'line': entry['line'],
                            'filename': new_name
                        })
                elif not new_vlan_set:
                    # Missing from this interface
                    for entry in baseline_interfaces_for_mac[interface]:
                        missing_entries_list.append({
                            'mac': mac,
                            'interface': interface,
                            'vlan': entry['vlan'],
                            'line': entry['line'],
                            'filename': baseline_name
                        })
                else:
                    # VLAN changed
                    vlan_changes.append({
                        'mac': mac,
                        'interface': interface,
                        'baseline_vlans': baseline_vlan_set,
                        'new_vlans': new_vlan_set,
                        'baseline_entries': baseline_interfaces_for_mac[interface],
                        'new_entries': new_interfaces_for_mac[interface],
                        'baseline_name': baseline_name,
                        'new_name': new_name
                    })
                processed_macs.add(mac)

def check_new_and_missing_macs(processed_macs, baseline_grouped, new_grouped,
                               new_entries_list, missing_entries_list, new_name, baseline_name):
    """Check for completely new and missing MACs"""
    # Check for completely new MACs (not in baseline at all)
    for (mac, interface), new_entries in new_grouped.items():
        if mac in processed_macs:
            continue
            
        if (mac, interface) not in baseline_grouped:
            # Completely new MAC+interface combination
            for entry in new_entries:
                new_entries_list.append({
                    'mac': mac,
                    'interface': interface,
                    'vlan': entry['vlan'],
                    'line': entry['line'],
                    'filename': new_name
                })
            processed_macs.add(mac)

    # Check for completely missing MACs (not in new at all)
    for (mac, interface), baseline_entries in baseline_grouped.items():
        if mac in processed_macs:
            continue
            
        if (mac, interface) not in new_grouped:
            # Completely missing MAC+interface combination
            for entry in baseline_entries:
                missing_entries_list.append({
                    'mac': mac,
                    'interface': interface,
                    'vlan': entry['vlan'],
                    'line': entry['line'],
                    'filename': baseline_name
                })
            processed_macs.add(mac)

def group_and_format_moves(moves_list, differences):
    """Group and format MAC moves by pattern"""
    if not moves_list:
        return
        
    move_groups = defaultdict(list)
    for move in moves_list:
        # Create key based on move pattern
        from_vlans_sorted = tuple(sorted(move['from_vlans']))
        to_vlans_sorted = tuple(sorted(move['to_vlans']))
        key = (move['from_interface'], move['to_interface'], from_vlans_sorted, to_vlans_sorted)
        move_groups[key].append(move)
    
    # Format grouped moves
    for (from_interface, to_interface, from_vlans, to_vlans), moves in move_groups.items():
        first_move = moves[0]
        if from_vlans != to_vlans:
            differences.append(f"MAC {first_move['mac']} moved from interface {from_interface} to {to_interface} and VLAN changed from {list(from_vlans)} to {list(to_vlans)}")
        else:
            differences.append(f"MAC {first_move['mac']} moved from interface {from_interface} to {to_interface}")
        
        for entry in first_move['baseline_entries']:
            differences.append(f"  {first_move['baseline_name']}: {entry['line']}")
        for entry in first_move['new_entries']:
            differences.append(f"  {first_move['new_name']}: {entry['line']}")
        
        # List other MACs with same move pattern
        other_macs = [move['mac'] for move in moves[1:]]
        if other_macs:
            differences.append("Other MACs have same results:")
            for mac in other_macs:
                differences.append(f"- MAC {mac}")

def group_and_format_entries(entries_list, differences, entry_type):
    """Generic function to group and format new/missing entries"""
    if not entries_list:
        return
        
    # Group by interface and VLAN
    groups = defaultdict(list)
    for entry in entries_list:
        # Normalize VLAN representation for grouping
        vlan_key = entry['vlan'] if isinstance(entry['vlan'], str) else str(sorted(entry['vlan']) if isinstance(entry['vlan'], set) else entry['vlan'])
        key = (entry['interface'], vlan_key)
        groups[key].append(entry)
    
    # Format grouped entries
    for (interface, vlan_key), entries in groups.items():
        first_entry = entries[0]
        # Display VLAN properly (without brackets for single VLAN)
        if isinstance(first_entry['vlan'], list) and len(first_entry['vlan']) == 1:
            vlan_display = first_entry['vlan'][0]
        elif isinstance(first_entry['vlan'], str):
            vlan_display = first_entry['vlan']
        else:
            vlan_display = first_entry['vlan']
            
        differences.append(f"MAC {first_entry['mac']} is {entry_type} in {first_entry['filename']} on interface {interface} with VLAN {vlan_display}")
        differences.append(f"  {first_entry['filename']}: {first_entry['line']}")
        
        # List other MACs with same pattern
        other_macs = [entry['mac'] for entry in entries[1:]]
        if other_macs:
            differences.append("Other MACs have same results:")
            for mac in other_macs:
                differences.append(f"- MAC {mac}")

def group_and_format_vlan_changes(vlan_changes, differences):
    """Group and format VLAN changes"""
    if not vlan_changes:
        return
        
    # Group by interface and VLAN change pattern
    vlan_groups = defaultdict(list)
    for change in vlan_changes:
        # Convert sets to sorted lists for consistent grouping
        baseline_vlans_sorted = tuple(sorted(change['baseline_vlans']))
        new_vlans_sorted = tuple(sorted(change['new_vlans']))
        key = (change['interface'], baseline_vlans_sorted, new_vlans_sorted)
        vlan_groups[key].append(change)
    
    # Format grouped VLAN changes
    for (interface, baseline_vlans, new_vlans), changes in vlan_groups.items():
        # Show details for the first entry
        first_change = changes[0]
        differences.append(f"MAC {first_change['mac']} on interface {interface} VLAN changed from {list(baseline_vlans)} to {list(new_vlans)}")
        for entry in first_change['baseline_entries']:
            differences.append(f"  {first_change['baseline_name']}: {entry['line']}")
        for entry in first_change['new_entries']:
            differences.append(f"  {first_change['new_name']}: {entry['line']}")
        
        # List other MACs with same change pattern
        other_macs = [change['mac'] for change in changes[1:]]
        if other_macs:
            differences.append("Other MACs have same results:")
            for mac in other_macs:
                differences.append(f"- MAC {mac}")

def detect_interface_swaps(mac_moves, potential_swaps):
    """Detect possible interface swaps"""
    # Group moves by interface pair
    interface_move_groups = defaultdict(list)
    for move in mac_moves:
        # Create a consistent key for interface pairs (sorted)
        interface_pair = tuple(sorted([move['from_interface'], move['to_interface']]))
        interface_move_groups[interface_pair].append(move)
    
    # For each interface pair, look for MACs moving in opposite directions
    for interface_pair, moves in interface_move_groups.items():
        # Group moves by direction
        direction1_moves = [move for move in moves if move['from_interface'] == interface_pair[0] and move['to_interface'] == interface_pair[1]]
        direction2_moves = [move for move in moves if move['from_interface'] == interface_pair[1] and move['to_interface'] == interface_pair[0]]
        
        # If we have moves in both directions, we might have a swap
        if direction1_moves and direction2_moves:
            # Only report one example pair to avoid too many duplicates
            move1 = direction1_moves[0]
            move2 = direction2_moves[0]
            potential_swaps.append((move1['mac'], move2['mac'], move1['from_interface'], move1['to_interface']))

def compare_mac_tables(file1, file2):
    """
    Compare two MAC table files and print differences
    Use the file with earlier timestamp as baseline
    """
    # Extract timestamps from filenames
    timestamp1 = extract_timestamp_from_filename(file1)
    timestamp2 = extract_timestamp_from_filename(file2)
    
    # Determine baseline file (earlier timestamp) and new file (later timestamp)
    if timestamp1 and timestamp2:
        if timestamp1 <= timestamp2:
            baseline_file, new_file = file1, file2
            baseline_name, new_name = os.path.basename(file1), os.path.basename(file2)
        else:
            baseline_file, new_file = file2, file1
            baseline_name, new_name = os.path.basename(file2), os.path.basename(file1)
    else:
        # If timestamps can't be parsed, use file1 as baseline by default
        baseline_file, new_file = file1, file2
        baseline_name, new_name = os.path.basename(file1), os.path.basename(file2)
    
    print(f"\n{'='*80}")
    print(f"Comparing {baseline_name} (baseline) and {new_name} (new)")
    print(f"{'='*80}")
    
    mac_table_baseline = parse_mac_table(baseline_file)
    mac_table_new = parse_mac_table(new_file)
    
    if not mac_table_baseline and not mac_table_new:
        print("Both files are empty or could not be parsed.")
        return []
    elif not mac_table_baseline:
        print(f"{baseline_file} is empty or could not be parsed.")
        return []
    elif not mac_table_new:
        print(f"{new_file} is empty or could not be parsed.")
        return []

    baseline_grouped = group_entries_by_mac_interface(mac_table_baseline)
    new_grouped = group_entries_by_mac_interface(mac_table_new)
    
    baseline_macs = group_entries_by_mac_only(mac_table_baseline)
    new_macs = group_entries_by_mac_only(mac_table_new)

    differences = []
    mac_moves = []  # Track all MAC moves for detecting interface swaps
    potential_swaps = []  # Track potential interface swaps
    
    # Initialize lists for grouping entries
    vlan_changes = []  # Store VLAN changes for grouping
    new_entries_list = []  # Store new entries for grouping
    missing_entries_list = []  # Store missing entries for grouping
    moves_list = []  # Store moves for grouping

    # Check for MAC moves (same MAC, different interfaces)
    all_macs = set(baseline_macs.keys()) | set(new_macs.keys())
    processed_macs = detect_mac_moves(
        all_macs, baseline_macs, new_macs, baseline_grouped, new_grouped,
        moves_list, mac_moves, baseline_name, new_name
    )
    
    # Check for VLAN changes on same interface (when MAC didn't move)
    check_vlan_changes(
        all_macs, processed_macs, mac_table_baseline, mac_table_new,
        baseline_grouped, new_grouped, baseline_macs, new_macs,
        vlan_changes, new_entries_list, missing_entries_list,
        baseline_name, new_name
    )
    
    # Update processed_macs after VLAN changes check
    for mac in all_macs:
        if mac not in processed_macs:
            baseline_interfaces = {iface for iface, vlan, line in baseline_macs.get(mac, set())}
            new_interfaces = {iface for iface, vlan, line in new_macs.get(mac, set())}
            if baseline_interfaces == new_interfaces:
                processed_macs.add(mac)
    
    # Check for completely new and missing MACs
    check_new_and_missing_macs(
        processed_macs, baseline_grouped, new_grouped,
        new_entries_list, missing_entries_list, new_name, baseline_name
    )

    # Group and format all types of differences
    group_and_format_moves(moves_list, differences)
    group_and_format_vlan_changes(vlan_changes, differences)
    group_and_format_entries(new_entries_list, differences, "NEW")
    group_and_format_entries(missing_entries_list, differences, "Missing")
    
    # Check for possible interface swaps
    detect_interface_swaps(mac_moves, potential_swaps)

    # Print results
    if differences:
        # Count main differences (not the grouped MACs)
        main_diff_count = sum(1 for diff in differences if is_main_difference(diff))
                
        print(f"\nFound {main_diff_count} differences:")
        print("-" * 80)
        for diff in differences:
            if is_main_difference(diff):
                print(f"- {diff}")
            else:
                print(f"  {diff}")
        
        # Print potential interface swaps
        if potential_swaps:
            print("\nPossible interface swaps detected:")
            for mac1, mac2, interface1, interface2 in potential_swaps:
                print(f"- Interfaces {interface1} and {interface2} might be reversed (MACs {mac1} and {mac2} swapped)")
        print()  # Add a blank line at the end
    else:
        print("两张mac table完全一样")
    
    # Return the differences for saving to file
    result = differences[:]
    if potential_swaps:
        result.append("\nPossible interface swaps detected:")
        for mac1, mac2, interface1, interface2 in potential_swaps:
            result.append(f"- Interfaces {interface1} and {interface2} might be reversed (MACs {mac1} and {mac2} swapped)")
    
    return result

def get_files_with_same_hostname(directory):
    """
    Group files by hostname (prefix before timestamp)
    """
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist.")
        return {}
        
    try:
        files = os.listdir(directory)
    except PermissionError:
        print(f"Permission denied accessing directory {directory}.")
        return {}
    except Exception as e:
        print(f"Error accessing directory {directory}: {e}")
        return {}
        
    # Filter for txt files and exclude comparison files
    txt_files = [f for f in files if f.endswith('.txt') and not f.startswith('comparison')]
    
    # Group files by hostname
    hostname_groups = defaultdict(list)
    
    for filename in txt_files:
        # Extract hostname (everything before the timestamp)
        # Assuming format: hostname-YYYYMMDD-HHMMSS.txt
        parts = filename.split('-')
        if len(parts) >= 3:  # hostname-timestamp1-timestamp2.txt
            # Hostname is everything before the last two dash-separated parts
            hostname = '-'.join(parts[:-2])
            hostname_groups[hostname].append(filename)
        else:
            # If can't parse, use the whole name without extension as hostname
            hostname = filename.replace('.txt', '')
            hostname_groups[hostname].append(filename)
    
    return hostname_groups

def save_comparison_results(file1, file2, differences, comparison_directory):
    """
    Save comparison results to the same directory used for comparison
    """
    # Create output filename based on input filenames
    file1_name = os.path.splitext(os.path.basename(file1))[0]
    file2_name = os.path.splitext(os.path.basename(file2))[0]
    output_filename = f"comparison_{file1_name}_to_{file2_name}.txt"
    output_path = os.path.join(comparison_directory, output_filename)
    
    # Write results to file
    try:
        with open(output_path, 'w') as f:
            f.write(f"MAC Table Comparison Report\n")
            f.write(f"{'='*80}\n")
            f.write(f"Compared files:\n")
            f.write(f"  File 1: {file1}\n")
            f.write(f"  File 2: {file2}\n")
            f.write(f"Comparison time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Comparison directory: {comparison_directory}\n")
            f.write(f"{'='*80}\n\n")
            
            # Count main differences (not the grouped MACs)
            main_diff_count = sum(1 for diff in differences if is_main_difference(diff))
                    
            if differences:
                f.write(f"Found {main_diff_count} differences:\n")
                f.write("-" * 80 + "\n")
                for diff in differences:
                    if is_main_difference(diff):
                        f.write(f"- {diff}\n")
                    else:
                        f.write(f"  {diff}\n")
            else:
                f.write("两张mac table完全一样\n")
        
        print(f"Comparison results saved to: {output_path}")
        return output_path
    except PermissionError:
        print(f"Permission denied when writing to {output_path}")
        return None
    except Exception as e:
        print(f"Error saving results to {output_path}: {e}")
        return None

def get_comparison_directory():
    """
    Get the directory to use for comparison:
    - If command line argument provided, use that as subdirectory name
    - Otherwise, use today's date as subdirectory name
    """
    base_directory = '~/tesla-op/compare-mac'
    
    # Expand the tilde to the home directory
    base_directory = os.path.expanduser(base_directory)
    
    # Check if directory name is provided as command line argument
    if len(sys.argv) > 1:
        subdirectory = sys.argv[1]
        comparison_directory = os.path.join(base_directory, subdirectory)
        # Expand in case the subdirectory also contains a tilde
        comparison_directory = os.path.expanduser(comparison_directory)
        if not os.path.exists(comparison_directory):
            print(f"Warning: Directory {comparison_directory} does not exist.")
    else:
        # Use today's date as default
        today = datetime.datetime.now().strftime("%Y%m%d")
        comparison_directory = os.path.join(base_directory, today)
        # Expand in case the path contains a tilde
        comparison_directory = os.path.expanduser(comparison_directory)
    
    return comparison_directory

def main():
    # Get the directory to use for comparison
    directory = get_comparison_directory()
    print(f"Using directory for comparison: {directory}")
    
    # Check if directory exists
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist. Exiting.")
        return
    
    hostname_groups = get_files_with_same_hostname(directory)
    
    if not hostname_groups:
        print("No files found to compare.")
        return
    
    # Process each group of files with same hostname
    for hostname, files in hostname_groups.items():
        if len(files) >= 2:
            print(f"\n{'#'*80}")
            print(f"Found {len(files)} files for hostname '{hostname}':")
            for i, file in enumerate(files):
                print(f"  {i+1}. {file}")
            
            # Compare first two files
            file1_path = os.path.join(directory, files[0])
            file2_path = os.path.join(directory, files[1])
            
            # Perform comparison
            differences = compare_mac_tables(file1_path, file2_path)
            
            # Save results to the same directory used for comparison
            if differences is not None:
                save_comparison_results(file1_path, file2_path, differences, directory)
                
        elif len(files) == 1:
            print(f"\nOnly one file found for hostname '{hostname}': {files[0]} - Skipping comparison")

if __name__ == "__main__":
    main()