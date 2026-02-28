#!/usr/bin/env python3
"""
Ping Multiple Addresses Tool
This script allows users to ping multiple IP addresses or domains simultaneously,
with customizable parameters and detailed reporting of results.
"""

import argparse
import asyncio
import ipaddress
import re
import sys
from typing import List, Tuple, Dict


def parse_addresses(input_text: str) -> List[str]:
    """
    Parse addresses from input text.
    Supports various formats:
    - One address per line
    - Space-separated
    - Comma-separated
    - Semicolon-separated
    """
    # Replace commas, semicolons, and other separators with spaces for uniform processing
    cleaned_text = re.sub(r'[,\s;\t\n\r]+', ' ', input_text.strip())
    
    # Split by spaces and filter out empty strings
    potential_addresses = [addr.strip() for addr in cleaned_text.split() if addr.strip()]
    
    # Validate and collect valid addresses (IP or domain)
    valid_addresses = []
    for addr in potential_addresses:
        if is_valid_address(addr):
            valid_addresses.append(addr)
        else:
            print(f"Warning: Skipping invalid address '{addr}'")
    
    return valid_addresses


def is_valid_address(address: str) -> bool:
    """
    Check if the given string is a valid IPv4, IPv6, or domain name.
    """
    try:
        # Check if it's a valid IP address (IPv4 or IPv6)
        ipaddress.ip_address(address)
        return True
    except ValueError:
        # If not an IP address, check if it's a valid domain name
        # Simple domain validation: alphanumeric, hyphens, dots, and at least one dot
        # Allow letters, digits, hyphens, and dots but must not start/end with hyphen or dot
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, address)) and len(address) <= 253


async def ping_single_address(
    address: str,
    timeout: int = 2000,
    interval: float = 1.0,
    size: int = 64,
    count: int = 5
) -> Tuple[str, bool, str]:
    """
    Ping a single address and return the result.
    
    Args:
        address: The IP address or domain to ping
        timeout: Timeout in milliseconds
        interval: Interval between pings in seconds
        size: Size of ping packet in bytes
        count: Number of ping packets to send
    
    Returns:
        Tuple of (address, success, output)
    """
    import subprocess
    
    # Determine ping command based on OS
    if sys.platform.startswith('win'):
        # Windows ping command
        cmd = [
            'ping',
            '-n', str(count),
            '-w', str(timeout),
            address
        ]
        # On Windows, we don't specify packet size by default to avoid needing admin rights
    else:
        # Unix/Linux ping command
        cmd = [
            'ping',
            '-c', str(count),
            '-W', str(max(1, timeout // 1000)),  # Convert ms to seconds for timeout
            '-i', str(interval),
            address
        ]
        # Add size parameter for Unix systems (data size, excludes headers)
        if size != 64:
            cmd.insert(-1, '-s')
            cmd.insert(-1, str(max(1, size - 28)))  # Subtract header size (approximate)
    
    try:
        # Run the ping command asynchronously
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
        
        # Determine success based on platform
        if sys.platform.startswith('win'):
            # Windows: check for "Reply from" occurrences
            replies = output.count("Reply from")
            success = replies >= count
        else:
            # Unix: check for "x packets transmitted, x received" pattern
            # The output can have different formats and may span multiple lines:
            # - "X packets transmitted, Y received, Z% packet loss"
            # - "X packets transmitted, Y received" on separate lines like:
            #   "2 packets transmitted, 2 packets received, 0.0\n% packet loss"
            # We'll match across multiple lines to catch all variations
            # First, replace newlines with spaces to handle multi-line patterns
            flat_output = output.replace('\n', ' ')
            match = re.search(r'(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+packets?\s+received', flat_output)
            if match:
                transmitted, received = int(match.group(1)), int(match.group(2))
                # Success means we sent 'count' packets and got 'count' responses back
                success = (transmitted == count) and (received == count)
            else:
                # If we can't parse the output, assume failure
                success = False
        
        return address, success, output
    except Exception as e:
        return address, False, f"Error pinging {address}: {str(e)}"


async def ping_multiple_addresses(
    addresses: List[str],
    timeout: int = 2000,
    interval: float = 1.0,
    size: int = 64,
    count: int = 5
) -> Dict:
    """
    Ping multiple addresses concurrently and return results.
    
    Args:
        addresses: List of addresses to ping
        timeout: Timeout in milliseconds
        interval: Interval between pings in seconds
        size: Size of ping packet in bytes
        count: Number of ping packets to send
    
    Returns:
        Dictionary with summary and details of ping results
    """
    if not addresses:
        return {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'success_details': [],
            'failure_details': []
        }
    
    # Create tasks for all ping operations
    tasks = [
        ping_single_address(addr, timeout, interval, size, count)
        for addr in addresses
    ]
    
    # Execute all ping operations concurrently
    results = await asyncio.gather(*tasks)
    
    # Process results
    successful = []
    failed = []
    
    for address, success, output in results:
        if success:
            successful.append((address, output))
        else:
            failed.append((address, output))
    
    return {
        'total': len(addresses),
        'successful': len(successful),
        'failed': len(failed),
        'success_details': successful,
        'failure_details': failed
    }


def print_report(results: Dict, show_successful: bool = True):
    """
    Print a formatted report of ping results.
    """
    print("\n" + "="*60)
    print("PING MULTIPLE ADDRESSES REPORT")
    print("="*60)
    print(f"Total addresses tested: {results['total']}")
    print(f"Successful: {results['successful']}")
    print(f"Failed: {results['failed']}")
    print("-"*60)
    
    if results['failure_details']:
        print("FAILED ADDRESSES DETAILS:")
        print("-"*60)
        
        # If there are more than 10 failed addresses, implement pagination
        total_failed = len(results['failure_details'])
        if total_failed > 10:
            # Show first 10 failures
            first_batch = results['failure_details'][:10]
            remaining_failures = results['failure_details'][10:]
            
            # Print first batch
            for address, output in first_batch:
                # Extract packet statistics from the output
                stats_match = re.search(r'(\d+) packets transmitted, (\d+) packets received', output.replace('\n', ' '))
                if stats_match:
                    transmitted = stats_match.group(1)
                    received = stats_match.group(2)
                    # Now look for packet loss percentage
                    loss_match = re.search(r'(\d+\.?\d*%) packet loss', output)
                    if loss_match:
                        packet_loss = loss_match.group(1)
                        stats_line = f"{transmitted} packets transmitted, {received} packets received, {packet_loss} packet loss"
                    else:
                        stats_line = f"{transmitted} packets transmitted, {received} packets received, Unknown packet loss"
                elif "Unknown host" in output or "cannot resolve" in output:
                    stats_line = "0 packets transmitted, 0 packets received, 100.0% packet loss (Unknown host)"
                else:
                    stats_line = "Unknown packet statistics"
                
                print(f"\nAddress: {address}")
                print(f"Stats: {stats_line}")
                print("-"*60)
            
            print(f"\nShowing first 10 of {total_failed} failed addresses.\n")
            
            # Ask if user wants to see more
            show_more = input(f"Do you want to see the remaining {len(remaining_failures)} failed addresses? (y/n): ").lower().strip()
            
            if show_more in ['y', 'yes']:
                # Ask how many more to show
                default_show = min(10, len(remaining_failures))
                count_input = input(f"How many more failed addresses to show? (default: {default_show}, max: {len(remaining_failures)}): ")
                
                if count_input.strip() == "":
                    show_count = default_show
                else:
                    try:
                        show_count = int(count_input)
                        show_count = min(show_count, len(remaining_failures))  # Don't exceed available failures
                        show_count = max(0, show_count)  # Don't go below 0
                    except ValueError:
                        print(f"Invalid input, showing default: {default_show}")
                        show_count = default_show
                
                # Show the requested number of additional failures
                additional_failures = remaining_failures[:show_count]
                print(f"\nShowing {len(additional_failures)} more failed addresses:\n")
                
                for address, output in additional_failures:
                    # Extract packet statistics from the output
                    stats_match = re.search(r'(\d+) packets transmitted, (\d+) packets received', output.replace('\n', ' '))
                    if stats_match:
                        transmitted = stats_match.group(1)
                        received = stats_match.group(2)
                        # Now look for packet loss percentage
                        loss_match = re.search(r'(\d+\.?\d*%) packet loss', output)
                        if loss_match:
                            packet_loss = loss_match.group(1)
                            stats_line = f"{transmitted} packets transmitted, {received} packets received, {packet_loss} packet loss"
                        else:
                            stats_line = f"{transmitted} packets transmitted, {received} packets received, Unknown packet loss"
                    elif "Unknown host" in output or "cannot resolve" in output:
                        stats_line = "0 packets transmitted, 0 packets received, 100.0% packet loss (Unknown host)"
                    else:
                        stats_line = "Unknown packet statistics"
                    
                    print(f"\nAddress: {address}")
                    print(f"Stats: {stats_line}")
                    print("-"*60)
                
                if show_count < len(remaining_failures):
                    print(f"\nShowing {show_count} of {len(remaining_failures)} remaining failed addresses.")
                else:
                    print(f"\nAll remaining {len(remaining_failures)} failed addresses shown.")
        else:
            # Show all failures if 10 or fewer
            for address, output in results['failure_details']:
                # Extract packet statistics from the output
                stats_match = re.search(r'(\d+) packets transmitted, (\d+) packets received', output.replace('\n', ' '))
                if stats_match:
                    transmitted = stats_match.group(1)
                    received = stats_match.group(2)
                    # Now look for packet loss percentage
                    loss_match = re.search(r'(\d+\.?\d*%) packet loss', output)
                    if loss_match:
                        packet_loss = loss_match.group(1)
                        stats_line = f"{transmitted} packets transmitted, {received} packets received, {packet_loss} packet loss"
                    else:
                        stats_line = f"{transmitted} packets transmitted, {received} packets received, Unknown packet loss"
                elif "Unknown host" in output or "cannot resolve" in output:
                    stats_line = "0 packets transmitted, 0 packets received, 100.0% packet loss (Unknown host)"
                else:
                    stats_line = "Unknown packet statistics"
                
                print(f"\nAddress: {address}")
                print(f"Stats: {stats_line}")
                print("-"*60)
    
    # Only show successful addresses if explicitly requested
    if show_successful and results['success_details']:
        print("\nSUCCESSFUL ADDRESSES:")
        print("-"*60)
        for address, _ in results['success_details']:
            print(f"- {address}")


def get_user_input_with_default(prompt: str, default_value) -> any:
    """
    Get user input with a default value.
    If user presses Enter, return the default value.
    Otherwise, return the user input converted to the same type as default.
    """
    user_input = input(f"{prompt} (default: {default_value}): ")
    if user_input.strip() == "":
        return default_value
    try:
        # Convert to the same type as default_value
        if isinstance(default_value, int):
            return int(user_input)
        elif isinstance(default_value, float):
            return float(user_input)
        else:
            return user_input
    except ValueError:
        print(f"Invalid input, using default value: {default_value}")
        return default_value


def main():
    parser = argparse.ArgumentParser(description='Ping multiple addresses with customizable parameters.')
    parser.add_argument(
        'addresses',
        nargs='?',
        help='Addresses to ping (can be provided as text input)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=2000,
        help='Timeout in milliseconds (default: 2000)'
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='Interval between pings in seconds (default: 1.0)'
    )
    parser.add_argument(
        '--size',
        type=int,
        default=64,
        help='Size of ping packet in bytes (default: 64)'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=5,
        help='Number of ping packets to send (default: 5)'
    )
    
    args = parser.parse_args()
    
    # Get input either from command line argument or stdin
    if args.addresses:
        input_text = args.addresses
    else:
        print("Enter addresses to ping (press Ctrl+D or Ctrl+Z when done):\n")
        input_text = sys.stdin.read()
    
    # Parse addresses
    addresses = parse_addresses(input_text)
    
    if not addresses:
        print("No valid addresses found. Please check your input.")
        return
    
    print(f"Parsing complete. Found {len(addresses)} valid addresses to ping.\n")
    
    # Ask user if they want to change default parameters
    change_params = input("Would you like to change the default parameters? (y/n): ").lower().strip()
    
    if change_params in ['y', 'yes']:
        print("\nAdjusting ping parameters (press Enter to keep default value):\n")
        timeout = get_user_input_with_default("Timeout in milliseconds", args.timeout)
        interval = get_user_input_with_default("Interval between pings in seconds", args.interval)
        size = get_user_input_with_default("Size of ping packet in bytes", args.size)
        count = get_user_input_with_default("Number of ping packets to send", args.count)
    else:
        timeout = args.timeout
        interval = args.interval
        size = args.size
        count = args.count
    
    print(f"\nParameters: timeout={timeout}ms, interval={interval}s, size={size}bytes, count={count}\n")
    
    # Run ping operations
    print("Pinging addresses...\n")
    results = asyncio.run(ping_multiple_addresses(
        addresses,
        timeout=timeout,
        interval=interval,
        size=size,
        count=count
    ))
    
    # Print results (only showing failed addresses, not successful ones)
    print_report(results, show_successful=False)


if __name__ == "__main__":
    main()