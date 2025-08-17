#!/usr/bin/env python3
import paramiko
import os
from scp import SCPClient
import sys
import datetime

# Common credentials for both devices
username = 'regress'
password = 'MaRtInI'

# Base local directory to save files
base_local_directory = os.path.expanduser('~/tesla-op/rsi-varlog')

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

def get_date():
    """Get current date in YYYYMMDD format"""
    return datetime.datetime.now().strftime("%Y%m%d")

def main():
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get date for this session
    date = get_date()
    
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    print(f"使用日期: {date}")
    
    # Create local directory with date only
    local_directory = os.path.join(base_local_directory, date)
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
                timeout=30  # Increased timeout for longer operations
            )
            
            # Generate filenames with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            rsi_filename = f"{device['hostname']}-rsi-{timestamp}.txt"
            varlog_filename = f"{device['hostname']}-varlog-{timestamp}.tgz"
            
            # 1. Collect RSI
            rsi_command = f"request support information | save {rsi_filename}"
            print(f"执行RSI命令: cli -c '{rsi_command}'")
            
            stdin, stdout, stderr = ssh.exec_command(f"cli -c '{rsi_command}'")
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功生成RSI文件")
                
                # Download the RSI file
                remote_rsi_path = f"/var/home/{username}/{rsi_filename}"
                local_rsi_path = os.path.join(local_directory, rsi_filename)
                
                print(f"正在从 {device['hostname']} 下载RSI文件...")
                download_file(ssh, remote_rsi_path, local_rsi_path)
                print(f"RSI文件已成功下载到 {local_rsi_path}")
            else:
                print(f"在 {device['hostname']} 上生成RSI文件时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # 2. Collect and compress varlog
            varlog_command = f"file archive compress source /var/log/* destination /var/tmp/{varlog_filename}"
            print(f"执行varlog命令: cli -c '{varlog_command}'")
            
            stdin, stdout, stderr = ssh.exec_command(f"cli -c '{varlog_command}'")
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功生成varlog压缩文件")
                
                # Download the varlog file
                remote_varlog_path = f"/var/tmp/{varlog_filename}"
                local_varlog_path = os.path.join(local_directory, varlog_filename)
                
                print(f"正在从 {device['hostname']} 下载varlog压缩文件...")
                download_file(ssh, remote_varlog_path, local_varlog_path)
                print(f"varlog压缩文件已成功下载到 {local_varlog_path}")
            else:
                print(f"在 {device['hostname']} 上生成varlog压缩文件时出错")
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