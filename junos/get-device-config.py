#!/usr/bin/env python3
import paramiko
import os
from scp import SCPClient
import sys

# Common credentials for both devices
username = 'regress'
password = 'MaRtInI'

# Local directory to save files - changed to ~/tesla-op/compare-files
local_directory = os.path.expanduser('~/tesla-op/compare-files')

def create_ssh_client():
    """Create and return an SSH client"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client

def download_file(ssh_client, remote_path, local_path):
    """Download file from remote server using SCP"""
    with SCPClient(ssh_client.get_transport()) as scp:
        scp.get(remote_path, local_path)

def get_device_info():
    """Get device information from user input using Ctrl+D to end"""
    devices = []
    print("请输入设备信息，每行格式为：hostname ip_address")
    print("例如：vqfx1_re 10.207.219.187")
    print("输入完成后按 Ctrl+D (EOF) 结束输入：")
    
    try:
        while True:
            line = input().strip()
            if line:
                parts = line.split()
                if len(parts) == 2:
                    devices.append({
                        'hostname': parts[0],
                        'ip': parts[1]
                    })
                else:
                    print(f"格式错误，跳过: {line}")
    except EOFError:
        # This is expected when user presses Ctrl+D
        pass
    
    return devices

def process_hostname(hostname):
    """Remove '_re' suffix from hostname and add '-config'"""
    if hostname.endswith('_re'):
        return hostname[:-3] + '-config'  # Remove '_re' and add '-config'
    else:
        return hostname + '-config'  # Just add '-config'


def get_config_mode():
    """Get configuration mode from user selection"""
    print("\n请选择配置获取模式:")
    print("1. set mode")
    print("   命令: show configuration | display set | except \"set version\" | save {hostname}.txt")
    print("2. set mode without default groups")
    print("   命令: show configuration | display set | except \"set version\" | except \"groups global\" | except \"groups member0\" | except \"groups re0\" | except \"groups re1\" | save {hostname}.txt")
    print("3. config mode")
    print("   命令: show configuration | save {hostname}.txt")
    print("4. config mode with inheritance from group")
    print("   命令: show configuration | display inheritance no-comments | save {hostname}.txt")
    print("5. config mode without groups")
    print("   命令: show configuration | find ^system | save {hostname}.txt")
    
    while True:
        try:
            choice = input("请输入选项编号 (1-5): ").strip()
            if choice in ['1', '2', '3', '4', '5']:  
                return int(choice)
            else:
                print("请输入有效的选项编号 (1-5)")
        except EOFError:
            # Default to option 1 if EOF
            return 1

def get_command_by_mode(mode, hostname):
    """Get the appropriate command based on selected mode"""
    # Process hostname to create the new filename format
    new_filename = process_hostname(hostname) + '.txt'
    
    commands = {
        1: f"show configuration | display set | except \"set version\" | save {new_filename}",
        2: f"show configuration | display set | except \"set version\" | except \"groups global\" | except \"groups member0\" | except \"groups re0\" | except \"groups re1\" | save {new_filename}",
        3: f"show configuration | save {new_filename}",
        4: f"show configuration | display inheritance no-comments | save {new_filename}",
        5: f"show configuration | find ^system | save {new_filename}"
    }
    return commands.get(mode, commands[1])  # Default to mode 1


def main():
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get configuration mode
    config_mode = get_config_mode()
    mode_names = {
        1: "set mode",
        2: "set mode without default groups",
        3: "config mode",
        4: "config mode with inheritance from group",
        5: "config mode without groups"
    }
    
    print(f"选择模式: {mode_names[config_mode]}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create local directory if it doesn't exist
    os.makedirs(local_directory, exist_ok=True)
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Get command based on selected mode
            command = get_command_by_mode(config_mode, device['hostname'])
            print(f"执行命令: cli -c '{command}'")
            
            stdin, stdout, stderr = ssh.exec_command(f"cli -c '{command}'")
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功保存配置")
                
                # Process hostname for file naming
                new_filename = process_hostname(device['hostname']) + '.txt'
                
                # Download the file
                remote_file_path = f"/var/home/{username}/{new_filename}"
                local_file_path = os.path.join(local_directory, new_filename)
                
                print(f"正在从 {device['hostname']} 下载文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"文件已成功下载到 {local_file_path}")
            else:
                print(f"在 {device['hostname']} 上执行命令时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # Close SSH connection
            ssh.close()
            
        except Exception as e:
            print(f"连接 {device['hostname']} 时出错: {str(e)}")
            continue

if __name__ == "__main__":
    main()