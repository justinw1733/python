#!/usr/bin/env python3
import paramiko
import os
import shutil
from scp import SCPClient
import sys
from datetime import datetime

# Common credentials for devices
username = 'regress'
password = 'MaRtInI'

# Local directories to save files
main_directory = '~/tesla-op/compare-mac'
backup_directory = '~/tesla-op/backup'

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
    """Remove '_re' suffix from hostname if present"""
    if hostname.endswith('_re'):
        return hostname[:-3]  # Remove '_re'
    else:
        return hostname

def get_timestamp():
    """Get current timestamp in YYYYMMDD-HHMMSS format"""
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def get_date_directory(base_directory):
    """Get date-based subdirectory path"""
    # Expand the tilde to home directory
    expanded_base_directory = os.path.expanduser(base_directory)
    today = datetime.now().strftime("%Y%m%d")
    date_directory = os.path.join(expanded_base_directory, today)
    os.makedirs(date_directory, exist_ok=True)
    return date_directory

def main():
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create date-based subdirectories for both main and backup locations
    main_date_directory = get_date_directory(main_directory)
    backup_date_directory = get_date_directory(backup_directory)
    
    print(f"文件将保存到主目录: {main_date_directory}")
    print(f"文件将备份到目录: {backup_date_directory}")
    
    # Generate timestamp for this run
    timestamp = get_timestamp()
    
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
            
            # Process hostname for file naming
            base_hostname = process_hostname(device['hostname'])
            filename = f"{base_hostname}-{timestamp}.txt"
            
            # Command to execute
            command = f"show ethernet-switching table | save {filename}"
            print(f"执行命令: cli -c '{command}'")
            
            stdin, stdout, stderr = ssh.exec_command(f"cli -c '{command}'")
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功保存MAC表")
                
                # Download the file to main directory
                remote_file_path = f"/var/home/{username}/{filename}"
                main_local_file_path = os.path.join(main_date_directory, filename)
                
                print(f"正在从 {device['hostname']} 下载文件到主目录...")
                download_file(ssh, remote_file_path, main_local_file_path)
                print(f"文件已成功下载到主目录: {main_local_file_path}")
                
                # Copy the file to backup directory
                backup_local_file_path = os.path.join(backup_date_directory, filename)
                shutil.copy2(main_local_file_path, backup_local_file_path)
                print(f"文件已成功备份到: {backup_local_file_path}")
                
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