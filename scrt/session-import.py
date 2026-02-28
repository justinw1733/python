#!/usr/bin/env python3
# $language = "Python"
# $interface = "1.0"

import os
import platform

# Detect the operating system and set the SecureCRT Sessions directory accordingly
system_platform = platform.system()
if system_platform == "Windows":
    # Windows path - corrected for your installation
    sessions_folder = os.path.expanduser("~/AppData/Roaming/VanDyke/Config/Sessions")
elif system_platform == "Darwin":
    # macOS path
    sessions_folder = os.path.expanduser("/Users/justinw/Library/Application Support/VanDyke/SecureCRT/Config/Sessions")
else:
    # Linux or other Unix-like systems
    sessions_folder = os.path.expanduser("~/.vandyke/SecureCRT/Config/Sessions")

def parse_hosts_input(hosts_text):
    """
    Parse host information text input
    Format: session_name ip_address
    """
    sessions = []
    lines = hosts_text.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:  # Skip empty lines
            continue
            
        parts = line.split()
        if len(parts) >= 2:
            session_name = parts[0]
            hostname = parts[1]
            
            session = {
                "name": session_name,
                "hostname": hostname
            }
            sessions.append(session)
        else:
            print(f"Warning: Could not parse line '{line}', please ensure format is 'session_name ip_address'")
    
    return sessions

def create_ssh_session(session, group_name, username):
    """
    Create SSH session file with automatic cli command execution
    """
    # Create session directory (if it doesn't exist)
    session_path = os.path.join(sessions_folder, group_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
    
    # Create .ini file
    ini_filename = f"{session['name']}.ini"
    ini_path = os.path.join(session_path, ini_filename)
    
    with open(ini_path, "w") as f:
        f.write(f"""S:"Session Name"={session['name']}
S:"Hostname"={session['hostname']}
S:"Username"={username}
S:"Protocol Name"=SSH2
D:"Port"=22
S:"Initial Terminal Shell Command"=cli
""")

def create_telnet_session(session, group_name, username):
    """
    Create Telnet session file
    """
    # Create session directory (if it doesn't exist)
    session_path = os.path.join(sessions_folder, group_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
    
    # Create .ini file
    ini_filename = f"{session['name']}.ini"
    ini_path = os.path.join(session_path, ini_filename)
    
    with open(ini_path, "w") as f:
        f.write(f"""S:"Session Name"={session['name']}
S:"Hostname"={session['hostname']}
S:"Username"={username}
S:"Protocol Name"=Telnet
D:"Port"=23
""")

def main():
    # Prompt for session type
    print("Please select session type to create:")
    print("1. SSH Session")
    print("2. Telnet Session")
    
    session_type = input("Please enter option (1 or 2): ").strip()
    while session_type not in ["1", "2"]:
        print("Invalid option, please enter 1 or 2")
        session_type = input("Please enter option (1 or 2): ").strip()
    
    # Set protocol-specific settings
    if session_type == "1":
        protocol = "SSH"
    else:
        protocol = "Telnet"
    
    # Prompt for credentials with defaults
    username = input(f"Enter {protocol} username (default: labroot): ").strip()
    if not username:
        username = "labroot"  # Default username
    
    # Note: Not prompting for password anymore since it should be set in SecureCRT after session creation
    print("NOTE: You will need to set and save the password in SecureCRT after importing the session")
    
    # Prompt for group name
    group_name = input("Enter group directory name: ").strip()
    if not group_name:
        group_name = f"Juniper-{protocol}-Sessions"  # Default group name
    
    print(f"Please enter host information, one per line in format 'session_name ip_address'")
    print("Example:")
    print("vmx1_re 10.207.202.191")
    print("vmx2_re 10.207.200.184")
    
    # Update instructions based on the detected platform
    if system_platform == "Windows":
        print("When finished entering hosts, press Ctrl+Z then Enter (Windows)")
    else:
        print("When finished entering hosts, press Ctrl+D (Mac/Linux)")
    
    # Read multi-line input
    hosts_input = ""
    try:
        while True:
            line = input()
            hosts_input += line + "\n"
    except EOFError:
        pass  # Ctrl+D or Ctrl+Z to finish input
    
    # Parse input host information
    sessions = parse_hosts_input(hosts_input)
    
    # Create all sessions
    for session in sessions:
        if session_type == "1":
            create_ssh_session(session, group_name, username)
        else:
            create_telnet_session(session, group_name, username)
        print(f"Created {protocol} session: {session['name']} -> {session['hostname']}")
    
    print(f"Successfully created {len(sessions)} {protocol} session(s)")
    print("Please set and save passwords in SecureCRT after importing these sessions")

if __name__ == "__main__":
    main()