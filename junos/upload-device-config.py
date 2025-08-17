#!/usr/bin/env python3
"""
Script to upload Junos configuration files and shell scripts to multiple devices,
then execute the shell script via SSH.
Supports batch processing with copy-paste input, Ctrl+D to end input.
Configuration files are located in ~/tesla-op/config-files/
Script files are located in ~/tesla-op/config-files/common/
"""

import paramiko
import sys
import os
import getpass
from scp import SCPClient

# Global variable to store selected subdirectory
selected_config_subdir = None

def create_ssh_client():
    """Create and return an SSH client instance"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return ssh

def create_scp_client(ssh):
    """Create and return an SCP client instance"""
    return SCPClient(ssh.get_transport())

def get_device_model(ssh, username):
    """
    Get device model by running appropriate commands based on user type
    If user is root, use cli -c command
    If user is other, use direct command
    
    Args:
        ssh: SSH client connection
        username (str): SSH username
        
    Returns:
        str: Device model type ('switch', 'router', or 'unknown')
    """
    try:
        print("Detecting device model...")
        
        # Determine command format based on username
        is_root = (username.lower() == "root")
        
        if is_root:
            print("Root user detected, using cli -c commands...")
            # For root user, use cli -c format
            stdin, stdout, stderr = ssh.exec_command(
                'cli -c "show chassis routing-engine | match model"', timeout=10
            )
        else:
            print("Non-root user detected, using direct commands...")
            # For non-root user, use direct commands
            stdin, stdout, stderr = ssh.exec_command(
                'show chassis routing-engine | grep model', timeout=10
            )
        
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            print(f"Command error: {error}")
        
        print(f"Model detection output: {output.strip()}")
        
        # Check output for device models
        combined_output = (output or "").upper()
        if "EX" in combined_output or "QFX" in combined_output:
            print("Detected switch model (EX/QFX)")
            return "switch"
        elif "MX" in combined_output or "PTX" in combined_output:
            print("Detected router model (MX/PTX)")
            return "router"
        else:
            print("Unknown device model")
            return "unknown"
            
    except Exception as e:
        print(f"Error detecting device model: {str(e)}")
        return "unknown"

def select_config_subdirectory(config_dir):
    """
    Let user select configuration subdirectory
    
    Args:
        config_dir (str): Base configuration directory
        
    Returns:
        str: Selected subdirectory path
    """
    # Get list of subdirectories
    subdirs = []
    if os.path.exists(config_dir):
        for item in os.listdir(config_dir):
            item_path = os.path.join(config_dir, item)
            if os.path.isdir(item_path):
                subdirs.append(item)
    
    if not subdirs:
        print("No subdirectories found in config directory")
        return ""
    
    # Display subdirectories with numbers
    print("\nAvailable configuration subdirectories:")
    for i, subdir in enumerate(subdirs, 1):
        print(f"{i}. {subdir}")
    
    # Get user selection
    while True:
        try:
            selection = input(f"Select subdirectory (1-{len(subdirs)}): ")
            index = int(selection) - 1
            if 0 <= index < len(subdirs):
                selected_subdir = subdirs[index]
                print(f"Selected subdirectory: {selected_subdir}")
                return os.path.join(config_dir, selected_subdir)
            else:
                print(f"Please enter a number between 1 and {len(subdirs)}")
        except ValueError:
            print("Please enter a valid number")

def get_config_path(hostname, config_base_dir):
    """
    Get the full path for configuration file based on hostname and selected subdirectory
    
    Args:
        hostname (str): Device hostname
        config_base_dir (str): Base configuration directory
        
    Returns:
        str: Path to configuration file
    """
    global selected_config_subdir
    
    # Remove _re suffix from hostname if present
    if hostname.endswith('_re'):
        base_hostname = hostname[:-3]  # Remove '_re' suffix
        print(f"Hostname with _re detected. Using '{base_hostname}' for config file lookup.")
    else:
        base_hostname = hostname
    
    # If subdirectory already selected, use it
    if selected_config_subdir is None:
        # Let user select subdirectory for the first device
        selected_config_subdir = select_config_subdirectory(config_base_dir)
        if not selected_config_subdir:
            selected_config_subdir = config_base_dir  # Fallback to base directory
    
    # Define config file name based on hostname (without _re)
    config_filename = f"{base_hostname}-config.txt"
    config_file = os.path.join(selected_config_subdir, config_filename)
    
    return config_file

def upload_files(hostname, ip, script_type, username, password):
    """
    Upload configuration and appropriate script files to the device
    
    Args:
        hostname (str): Device hostname
        ip (str): Device IP address
        script_type (str): Type of script to upload ('switch' or 'router')
        username (str): SSH username
        password (str): SSH password
    """
    try:
        # Create SSH connection
        ssh = create_ssh_client()
        print(f"Connecting to {hostname} ({ip})...")
        ssh.connect(ip, username=username, password=password, timeout=10)
        print("Connected successfully")
        
        # Determine which script to upload based on device model
        home_dir = os.path.expanduser("~")
        script_dir = os.path.join(home_dir, "tesla-op", "config-files", "common")
        
        if script_type == "switch":
            script_file = os.path.join(script_dir, "switch-setup.sh")
            script_name = "switch-setup.sh"
        elif script_type == "router":
            script_file = os.path.join(script_dir, "router-setup.sh")
            script_name = "router-setup.sh"
        else:
            print(f"Unknown script type: {script_type}")
            return None, None, None
        
        # Check if script file exists
        if not os.path.exists(script_file):
            print(f"Script file {script_file} not found")
            script_files = [f for f in os.listdir(script_dir) if f.endswith('.sh')]
            if script_files:
                print("Available script files:")
                for f in script_files:
                    print(f"  {f}")
            return None, None, None
        
        print(f"Using script: {script_file}")
        
        # Get config file path based on hostname with subdirectory selection
        config_base_dir = os.path.join(home_dir, "tesla-op", "config-files")
        config_file = get_config_path(hostname, config_base_dir)
        
        # Check if config file exists
        if not os.path.exists(config_file):
            print(f"Configuration file {config_file} not found")
            # List available config files in the selected directory
            config_dir = os.path.dirname(config_file)
            if os.path.exists(config_dir):
                config_files = [f for f in os.listdir(config_dir) if f.endswith('.txt')]
                if config_files:
                    print("Available configuration files in selected directory:")
                    for f in config_files:
                        print(f"  {f}")
            return None, None, None
        
        print(f"Using config file: {config_file}")
        
        # Create SCP client for file transfer
        scp = create_scp_client(ssh)
        
        # Upload configuration file
        print(f"Uploading {config_file} to {hostname}...")
        scp.put(config_file, f"/var/tmp/{os.path.basename(config_file)}")
        print("Configuration file uploaded successfully")
        
        # Upload appropriate script
        print(f"Uploading {script_file} to {hostname}...")
        scp.put(script_file, f"/var/tmp/{script_name}")
        print("Script file uploaded successfully")
        
        # Make script executable
        print("Setting execute permissions on script...")
        ssh.exec_command(f"chmod +x /var/tmp/{script_name}")
        
        # Close SCP connection
        scp.close()
        
        return ssh, script_name, os.path.basename(config_file)
        
    except Exception as e:
        print(f"Error uploading files to {hostname}: {str(e)}")
        return None, None, None

def execute_script(ssh, script_name):
    """
    Execute the uploaded shell script and wait for completion.
    """
    try:
        import time
        channel = ssh.invoke_shell()
        time.sleep(1)
        print("Starting shell mode...")
        channel.send('start shell\n')
        time.sleep(1)
        channel.send('\n')
        time.sleep(1)
        command = f'sh /var/tmp/{script_name}\n'
        print(f"Executing script: {command.strip()}")
        channel.send(command)
        time.sleep(1)

        output = ""
        start_time = time.time()
        timeout = 300  # 5 minutes timeout

        while True:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode(errors='ignore')
                output += chunk
                print(chunk, end='')
                # Check if configuration is complete
                if "commit complete" in chunk and "%" in chunk:
                    # Exit shell mode
                    channel.send('exit\n')
                    time.sleep(1)
                    break
            if time.time() - start_time > timeout:
                print("\nScript execution timeout.")
                break
            time.sleep(0.5)

        # Ensure we're out of shell mode
        channel.send('\n')
        time.sleep(1)
        channel.close()
        return True

    except Exception as e:
        print(f"Error executing script: {str(e)}")
        return False

def parse_host_input(lines):
    """
    Parse host input lines into hostname and IP pairs
    
    Args:
        lines (list): List of input lines
        
    Returns:
        list: List of tuples containing (hostname, ip)
    """
    hosts = []
    for line in lines:
        line = line.strip()
        if line:
            parts = line.split()
            if len(parts) >= 2:
                hostname = parts[0]
                ip = parts[1]
                hosts.append((hostname, ip))
            else:
                print(f"Warning: Skipping invalid line: {line}")
    return hosts

def main():
    """Main function"""
    print("Please enter host information (format: hostname ip_address)")
    print("Paste multiple lines, press Ctrl+D (or Ctrl+Z on Windows) when finished:")
    print("-" * 50)
    
    # Read input until EOF (Ctrl+D)
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        # Ctrl+D pressed, continue with processing
        pass
    
    # Parse host information
    hosts = parse_host_input(lines)
    
    if not hosts:
        print("No valid hosts provided. Exiting.")
        sys.exit(1)
    
    # Get credentials
    username = input("SSH Username: ")
    password = getpass.getpass("SSH Password: ")
    
    # Process each host
    for hostname, ip in hosts:
        print(f"\n{'='*60}")
        print(f"Processing host: {hostname} ({ip})")
        print(f"{'='*60}")
        
        try:
            # Create SSH connection to detect model
            ssh = create_ssh_client()
            print(f"Connecting to {hostname} ({ip}) for model detection...")
            ssh.connect(ip, username=username, password=password, timeout=10)
            print("Connected successfully")
            
            # Detect device model based on username
            model_type = get_device_model(ssh, username)
            ssh.close()
            
            if model_type == "unknown":
                print(f"Cannot determine device model for {hostname}. Skipping.")
                continue
            
            # Upload files with appropriate script
            ssh, script_name, config_filename = upload_files(hostname, ip, model_type, username, password)
            
            if ssh and script_name and config_filename:
                # Execute script
                execute_script(ssh, script_name)
                
                # Close connection
                ssh.close()
                print(f"Connection to {hostname} closed")
            else:
                print(f"Failed to upload files to {hostname}. Skipping.")
                
        except Exception as e:
            print(f"Error processing {hostname}: {str(e)}")
            continue
    
    print(f"\nAll hosts processed.")

if __name__ == "__main__":
    main()