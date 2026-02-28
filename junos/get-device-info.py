#!/usr/bin/env python3
import paramiko
import os
from scp import SCPClient
import sys
import getpass
import argparse
from datetime import datetime

def create_ssh_client():
    """Create and return an SSH client"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client

def download_file(ssh_client, remote_path, local_path):
    """Download file from remote server using SCP"""
    with SCPClient(ssh_client.get_transport()) as scp:
        scp.get(remote_path, local_path)

def get_credentials():
    """Get username and password from user input with defaults"""
    print("\n请输入登录凭据:")
    
    # Get username with default
    username_input = input("用户名 [默认: labroot]: ").strip()
    username = username_input if username_input else 'labroot'
    
    # Get password with default (hidden input)
    password_input = getpass.getpass("密码 [默认: lab123]: ")
    password = password_input if password_input else 'lab123'
    
    return username, password

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

def process_hostname_with_options(hostname, args):
    """Remove '_re' suffix from hostname and add option suffixes with optional date/time"""
    # Remove '_re' suffix if present
    if hostname.endswith('_re'):
        base_name = hostname[:-3]
    else:
        base_name = hostname
    
    # Build option suffix
    option_suffix = ""
    if args.set:
        option_suffix += "-s"
    if args.nogroup:
        option_suffix += "-ng"
    if args.inheritance:
        option_suffix += "-i"
    
    # Add date and time only if requested
    date_time_suffix = ""
    if args.date or args.time:
        now = datetime.now()
        if args.date:
            date_time_suffix += "-" + now.strftime("%Y%m%d")
        if args.time:
            date_time_suffix += "-" + now.strftime("%H%M%S")
    
    # Construct final filename
    filename = f"{base_name}{option_suffix}-config{date_time_suffix}.txt"
    return filename

def get_save_directory():
    """Get save directory from user input with default"""
    default_dir = os.path.expanduser('~/tesla-op/config')
    print(f"\n请指定配置文件保存目录:")
    
    user_input = input(f"保存目录 [默认: {default_dir}]: ").strip()
    
    if user_input:
        # User specified a directory
        base_dir = os.path.expanduser(user_input)
    else:
        # Use default directory
        base_dir = default_dir
    
    return base_dir

def get_config_time_based_directory(base_dir):
    """Get the time-based subdirectory for storing config files"""
    now = datetime.now()
    time_subdir = now.strftime("%Y%m%d")
    return os.path.join(base_dir, time_subdir)

def get_rsi_time_based_directory(base_dir):
    """Get the time-based subdirectory for storing RSI files"""
    now = datetime.now()
    time_subdir = now.strftime("%Y%m%d")
    return os.path.join(base_dir, time_subdir)

def process_hostname_for_rsi(hostname, args):
    """Remove '_re' suffix from hostname and add RSI suffix with optional date/time"""
    # Remove '_re' suffix if present
    if hostname.endswith('_re'):
        base_name = hostname[:-3]
    else:
        base_name = hostname
    
    # Build option suffix
    option_suffix = ""
    if args.brief:
        option_suffix += "-brief"
    
    # Add date and time only if requested
    date_time_suffix = ""
    if args.date or args.time:
        now = datetime.now()
        if args.date:
            date_time_suffix += "-" + now.strftime("%Y%m%d")
        if args.time:
            date_time_suffix += "-" + now.strftime("%H%M%S")
    
    # Construct final filename
    filename = f"{base_name}{option_suffix}-rsi{date_time_suffix}.txt"
    return filename

def get_rsi_command_by_args(args, hostname, filename):
    """Get the appropriate RSI command based on command line arguments using provided filename"""
    # Build the command based on arguments
    if args.brief:
        command = "request support information brief"
    else:
        command = "request support information"
    
    command += f" | save {filename}"
    return command

def get_rsi_save_directory():
    """Get RSI save directory from user input with default"""
    default_dir = os.path.expanduser('~/tesla-op/rsi')
    print(f"\n请指定RSI文件保存目录:")
    
    user_input = input(f"保存目录 [默认: {default_dir}]: ").strip()
    
    if user_input:
        # User specified a directory
        base_dir = os.path.expanduser(user_input)
    else:
        # Use default directory
        base_dir = default_dir
    
    return base_dir

def get_rsi_mode_description(args):
    """Get description of the selected RSI mode"""
    description_parts = []
    
    if args.brief:
        description_parts.append("RSI brief mode")
    else:
        description_parts.append("RSI mode (default)")
    
    # Add date/time/backup options to description
    options = []
    if args.date:
        options.append("date")
    if args.time:
        options.append("time")
    if args.backup:
        options.append("backup")
    
    if options:
        description_parts.append(f"with {' and '.join(options)} enabled")
    
    return ", ".join(description_parts)


def parse_arguments():
    """Parse command line arguments with subcommands"""
    parser = argparse.ArgumentParser(
        description='Junos device management tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        required=True
    )
    
    # Config subcommand
    config_parser = subparsers.add_parser(
        'config',
        help='Get device configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                           # Default config mode
  %(prog)s --set                     # Set mode
  %(prog)s --set --nogroup           # Set mode without default groups
  %(prog)s --nogroup                 # Config mode without groups
  %(prog)s --inheritance             # Config mode with inheritance from group
  %(prog)s --date                    # Add date to filename
  %(prog)s --time                    # Add time to filename
  %(prog)s --date --time             # Add both date and time to filename
  %(prog)s --backup                  # Create backup copy
  %(prog)s --date --time --backup    # Add date, time and create backup
        '''
    )
    
    config_parser.add_argument('-s', '--set', action='store_true',
                              help='Use set mode (display set format)')
    config_parser.add_argument('-ng', '--nogroup', action='store_true',
                              help='Exclude default groups')
    config_parser.add_argument('-i', '--inheritance', action='store_true',
                              help='Show configuration with inheritance from group')
    config_parser.add_argument('-dt', '--date', action='store_true',
                              help='Add date to filename (YYYYMMDD format)')
    config_parser.add_argument('-tm', '--time', action='store_true',
                              help='Add time to filename (HHMMSS format)')
    config_parser.add_argument('-b', '--backup', action='store_true',
                              help='Create backup copy in ~/tesla-op/backup/config')
    
    # RSI subcommand
    rsi_parser = subparsers.add_parser(
        'rsi',
        help='Get RSI (Request Support Information) from device',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                           # Default RSI mode
  %(prog)s --brief                   # Brief RSI mode
  %(prog)s --date                    # Add date to filename
  %(prog)s --time                    # Add time to filename
  %(prog)s --date --time             # Add both date and time to filename
  %(prog)s --backup                  # Create backup copy
  %(prog)s --brief --date --backup   # Brief mode with date and backup
        '''
    )
    
    rsi_parser.add_argument('-b', '--brief', action='store_true',
                           help='Use brief mode for RSI')
    rsi_parser.add_argument('-dt', '--date', action='store_true',
                           help='Add date to filename (YYYYMMDD format)')
    rsi_parser.add_argument('-tm', '--time', action='store_true',
                           help='Add time to filename (HHMMSS format)')
    rsi_parser.add_argument('--backup', action='store_true',
                           help='Create backup copy in ~/tesla-op/backup/rsi')
    
    # Varlog subcommand
    varlog_parser = subparsers.add_parser(
        'varlog',
        help='Get varlog archive from device',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                           # Default varlog mode
  %(prog)s --date                    # Add date to filename
  %(prog)s --time                    # Add time to filename
  %(prog)s --date --time             # Add both date and time to filename
  %(prog)s --backup                  # Create backup copy
  %(prog)s --date --time --backup    # Add date, time and create backup
        '''
    )
    
    varlog_parser.add_argument('-dt', '--date', action='store_true',
                              help='Add date to filename (YYYYMMDD format)')
    varlog_parser.add_argument('-tm', '--time', action='store_true',
                              help='Add time to filename (HHMMSS format)')
    varlog_parser.add_argument('-b', '--backup', action='store_true',
                              help='Create backup copy in ~/tesla-op/backup/varlog')
    
    # LLDP subcommand
    lldp_parser = subparsers.add_parser(
        'lldp',
        help='Get LLDP neighbors information from device',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                           # Default LLDP mode
  %(prog)s --json                    # JSON format output
  %(prog)s --detail                  # Detailed LLDP neighbors information
  %(prog)s --detail --json           # Detailed LLDP neighbors in JSON format
  %(prog)s --date                    # Add date to filename
  %(prog)s --time                    # Add time to filename
  %(prog)s --date --time             # Add both date and time to filename
  %(prog)s --backup                  # Create backup copy
  %(prog)s --json --date --backup    # JSON mode with date and backup
  %(prog)s --detail --date --backup  # Detail mode with date and backup
        '''
    )
    
    lldp_parser.add_argument('-j', '--json', action='store_true',
                            help='Output in JSON format')
    lldp_parser.add_argument('-dtl', '--detail', action='store_true',
                            help='Show detailed LLDP neighbors information')
    lldp_parser.add_argument('-dt', '--date', action='store_true',
                            help='Add date to filename (YYYYMMDD format)')
    lldp_parser.add_argument('-tm', '--time', action='store_true',
                            help='Add time to filename (HHMMSS format)')
    lldp_parser.add_argument('-b', '--backup', action='store_true',
                            help='Create backup copy in ~/tesla-op/backup/lldp')
    
    # MAC-table subcommand
    mac_table_parser = subparsers.add_parser(
        'mac-table',
        help='Get Ethernet switching table from device',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                           # Default MAC table mode
  %(prog)s --date                    # Add date to filename
  %(prog)s --time                    # Add time to filename
  %(prog)s --date --time             # Add both date and time to filename
  %(prog)s --backup                  # Create backup copy
  %(prog)s --date --time --backup    # Add date, time and create backup
        '''
    )
    
    mac_table_parser.add_argument('-dt', '--date', action='store_true',
                                 help='Add date to filename (YYYYMMDD format)')
    mac_table_parser.add_argument('-tm', '--time', action='store_true',
                                 help='Add time to filename (HHMMSS format)')
    mac_table_parser.add_argument('-b', '--backup', action='store_true',
                                 help='Create backup copy in ~/tesla-op/backup/mac-table')
    
    return parser.parse_args()

def get_command_by_args(args, hostname, filename):
    """Get the appropriate command based on command line arguments using provided filename"""
    # Build the command based on arguments
    if args.set:
        # Set mode
        command = "show configuration | display set | except \"set version\""
        if args.nogroup:
            # Set mode without default groups
            command += ' | except "groups global" | except "groups member0" | except "groups re0" | except "groups re1"'
    elif args.inheritance:
        # Config mode with inheritance from group
        command = "show configuration | display inheritance no-comments"
    elif args.nogroup:
        # Config mode without groups
        command = "show configuration | find ^system"
    else:
        # Default config mode
        command = "show configuration"
    
    command += f" | save {filename}"
    return command

def get_mode_description(args):
    """Get description of the selected mode"""
    description_parts = []
    
    if args.set and args.nogroup:
        description_parts.append("set mode without default groups")
    elif args.set:
        description_parts.append("set mode")
    elif args.inheritance:
        description_parts.append("config mode with inheritance from group")
    elif args.nogroup:
        description_parts.append("config mode without groups")
    else:
        description_parts.append("config mode (default)")
    
    # Add date/time options to description
    options = []
    if args.date:
        options.append("date")
    if args.time:
        options.append("time")
    if args.backup:
        options.append("backup")
    
    if options:
        description_parts.append(f"with {' and '.join(options)} enabled")
    
    return ", ".join(description_parts)


def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Handle different commands
    if args.command == 'config':
        handle_config_command(args)
    elif args.command == 'rsi':
        handle_rsi_command(args)
    elif args.command == 'varlog':
        handle_varlog_command(args)
    elif args.command == 'lldp':
        handle_lldp_command(args)
    elif args.command == 'mac-table':
        handle_mac_table_command(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1

def handle_config_command(args):
    """Handle the config subcommand"""
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get credentials from user
    username, password = get_credentials()
    
    # Get save directory from user
    base_save_dir = get_save_directory()
    
    # Show selected mode
    mode_description = get_mode_description(args)
    print(f"选择模式: {mode_description}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create time-based local directory if it doesn't exist
    local_directory = get_config_time_based_directory(base_save_dir)
    os.makedirs(local_directory, exist_ok=True)
    print(f"配置文件将保存到: {local_directory}")
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Generate filename once to ensure consistency
            config_filename = process_hostname_with_options(device['hostname'], args)
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Get command based on arguments using the generated filename
            command = get_command_by_args(args, device['hostname'], config_filename)
            
            # Determine if we need cli -c wrapper based on username
            if username.lower() == 'root':
                full_command = f"cli -c '{command}'"
                print(f"执行命令: {full_command}")
            else:
                full_command = command
                print(f"执行命令: {full_command}")
            
            stdin, stdout, stderr = ssh.exec_command(full_command)
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功保存配置")
                
                # Use the same filename for download
                remote_file_path = f"/var/home/{username}/{config_filename}"
                local_file_path = os.path.join(local_directory, config_filename)
                
                print(f"正在从 {device['hostname']} 下载文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"文件已成功下载到 {local_file_path}")
                
                # Create backup copy if backup option is enabled
                if args.backup:
                    create_backup_copy(local_file_path, 'config')
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

def handle_rsi_command(args):
    """Handle the rsi subcommand"""
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get credentials from user
    username, password = get_credentials()
    
    # Get save directory from user
    base_save_dir = get_rsi_save_directory()
    
    # Show selected mode
    mode_description = get_rsi_mode_description(args)
    print(f"选择模式: {mode_description}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create time-based local directory if it doesn't exist
    local_directory = get_rsi_time_based_directory(base_save_dir)
    os.makedirs(local_directory, exist_ok=True)
    print(f"RSI文件将保存到: {local_directory}")
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Generate filename once to ensure consistency
            rsi_filename = process_hostname_for_rsi(device['hostname'], args)
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Get command based on arguments using the generated filename
            command = get_rsi_command_by_args(args, device['hostname'], rsi_filename)
            
            # Determine if we need cli -c wrapper based on username
            if username.lower() == 'root':
                full_command = f"cli -c '{command}'"
                print(f"执行命令: {full_command}")
            else:
                full_command = command
                print(f"执行命令: {full_command}")
            
            stdin, stdout, stderr = ssh.exec_command(full_command)
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功RSI保存")
                
                # Use the same filename for download
                remote_file_path = f"/var/home/{username}/{rsi_filename}"
                local_file_path = os.path.join(local_directory, rsi_filename)
                
                print(f"正在从 {device['hostname']} 下载RSI文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"RSI文件已成功下载到 {local_file_path}")
                
                # Create backup copy if backup option is enabled
                if args.backup:
                    create_backup_copy(local_file_path, 'rsi')
            else:
                print(f"在 {device['hostname']} 上执行RSI命令时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # Close SSH connection
            ssh.close()
            
        except Exception as e:
            print(f"连接 {device['hostname']} 时出错: {str(e)}")
            continue

def get_varlog_time_based_directory(base_dir):
    """Get the time-based subdirectory for storing varlog files"""
    now = datetime.now()
    time_subdir = now.strftime("%Y%m%d")
    return os.path.join(base_dir, time_subdir)

def process_hostname_for_varlog(hostname, args):
    """Remove '_re' suffix from hostname and add varlog suffix with optional date/time"""
    # Remove '_re' suffix if present
    if hostname.endswith('_re'):
        base_name = hostname[:-3]
    else:
        base_name = hostname
    
    # Add date and time only if requested
    date_time_suffix = ""
    if args.date or args.time:
        now = datetime.now()
        if args.date:
            date_time_suffix += "-" + now.strftime("%Y%m%d")
        if args.time:
            date_time_suffix += "-" + now.strftime("%H%M%S")
    
    # Construct final filename (for the archive name on device)
    filename = f"{base_name}-varlog{date_time_suffix}"
    return filename

def get_varlog_command_by_args(args, hostname, archive_name):
    """Get the appropriate varlog command based on command line arguments using provided archive name"""
    # Build the command - file archive compress source /var/log/* destination /var/tmp/archive_name
    command = f"file archive compress source /var/log/* destination /var/tmp/{archive_name}"
    return command

def get_varlog_save_directory():
    """Get varlog save directory from user input with default"""
    default_dir = os.path.expanduser('~/tesla-op/varlog')
    print(f"\n请指定varlog文件保存目录:")
    
    user_input = input(f"保存目录 [默认: {default_dir}]: ").strip()
    
    if user_input:
        # User specified a directory
        base_dir = os.path.expanduser(user_input)
    else:
        # Use default directory
        base_dir = default_dir
    
    return base_dir

def get_varlog_mode_description(args):
    """Get description of the selected varlog mode"""
    description_parts = ["varlog archive mode"]
    
    # Add date/time/backup options to description
    options = []
    if args.date:
        options.append("date")
    if args.time:
        options.append("time")
    if args.backup:
        options.append("backup")
    
    if options:
        description_parts.append(f"with {' and '.join(options)} enabled")
    
    return ", ".join(description_parts)

def handle_varlog_command(args):
    """Handle the varlog subcommand"""
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get credentials from user
    username, password = get_credentials()
    
    # Get save directory from user
    base_save_dir = get_varlog_save_directory()
    
    # Show selected mode
    mode_description = get_varlog_mode_description(args)
    print(f"选择模式: {mode_description}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create time-based local directory if it doesn't exist
    local_directory = get_varlog_time_based_directory(base_save_dir)
    os.makedirs(local_directory, exist_ok=True)
    print(f"varlog文件将保存到: {local_directory}")
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Generate archive name once to ensure consistency
            varlog_archive_name = process_hostname_for_varlog(device['hostname'], args)
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Get command based on arguments using the generated archive name
            command = get_varlog_command_by_args(args, device['hostname'], varlog_archive_name)
            
            # Determine if we need cli -c wrapper based on username
            if username.lower() == 'root':
                full_command = f"cli -c '{command}'"
                print(f"执行命令: {full_command}")
            else:
                full_command = command
                print(f"执行命令: {full_command}")
            
            stdin, stdout, stderr = ssh.exec_command(full_command)
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功创建varlog压缩文件")
                
                # Use the same archive name for download (add .tgz extension for the downloaded file)
                remote_file_path = f"/var/tmp/{varlog_archive_name}.tgz"
                local_file_path = os.path.join(local_directory, f"{varlog_archive_name}.tgz")
                
                print(f"正在从 {device['hostname']} 下载varlog文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"varlog文件已成功下载到 {local_file_path}")
                
                # Create backup copy if backup option is enabled
                if args.backup:
                    create_backup_copy(local_file_path, 'varlog')
            else:
                print(f"在 {device['hostname']} 上执行varlog命令时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # Close SSH connection
            ssh.close()
            
        except Exception as e:
            print(f"连接 {device['hostname']} 时出错: {str(e)}")
            continue

def get_lldp_time_based_directory(base_dir):
    """Get the time-based subdirectory for storing lldp files"""
    now = datetime.now()
    time_subdir = now.strftime("%Y%m%d")
    return os.path.join(base_dir, time_subdir)

def process_hostname_for_lldp(hostname, args):
    """Remove '_re' suffix from hostname and add lldp suffix with optional date/time"""
    # Remove '_re' suffix if present
    if hostname.endswith('_re'):
        base_name = hostname[:-3]
    else:
        base_name = hostname
    
    # Build option suffix
    option_suffix = ""
    if args.json:
        option_suffix += "-json"
    if args.detail:
        option_suffix += "-detail"
    
    # Add date and time only if requested
    date_time_suffix = ""
    if args.date or args.time:
        now = datetime.now()
        if args.date:
            date_time_suffix += "-" + now.strftime("%Y%m%d")
        if args.time:
            date_time_suffix += "-" + now.strftime("%H%M%S")
    
    # Construct final filename
    filename = f"{base_name}{option_suffix}-lldp{date_time_suffix}.txt"
    return filename

def get_lldp_command_by_args(args, hostname, filename):
    """Get the appropriate lldp command based on command line arguments using provided filename"""
    # Build the command based on arguments
    if args.detail and args.json:
        command = "show lldp neighbors detail | display json"
    elif args.detail:
        command = "show lldp neighbors detail"
    elif args.json:
        command = "show lldp neighbors | display json"
    else:
        command = "show lldp neighbors"
    
    command += f" | save {filename}"
    return command

def get_lldp_save_directory():
    """Get lldp save directory from user input with default"""
    default_dir = os.path.expanduser('~/tesla-op/lldp')
    print(f"\n请指定LLDP文件保存目录:")
    
    user_input = input(f"保存目录 [默认: {default_dir}]: ").strip()
    
    if user_input:
        # User specified a directory
        base_dir = os.path.expanduser(user_input)
    else:
        # Use default directory
        base_dir = default_dir
    
    return base_dir

def get_lldp_mode_description(args):
    """Get description of the selected lldp mode"""
    description_parts = []
    
    if args.detail and args.json:
        description_parts.append("LLDP neighbors detail JSON mode")
    elif args.detail:
        description_parts.append("LLDP neighbors detail mode")
    elif args.json:
        description_parts.append("LLDP neighbors JSON mode")
    else:
        description_parts.append("LLDP neighbors mode (default)")
    
    # Add date/time/backup options to description
    options = []
    if args.date:
        options.append("date")
    if args.time:
        options.append("time")
    if args.backup:
        options.append("backup")
    
    if options:
        description_parts.append(f"with {' and '.join(options)} enabled")
    
    return ", ".join(description_parts)

def handle_lldp_command(args):
    """Handle the lldp subcommand"""
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get credentials from user
    username, password = get_credentials()
    
    # Get save directory from user
    base_save_dir = get_lldp_save_directory()
    
    # Show selected mode
    mode_description = get_lldp_mode_description(args)
    print(f"选择模式: {mode_description}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create time-based local directory if it doesn't exist
    local_directory = get_lldp_time_based_directory(base_save_dir)
    os.makedirs(local_directory, exist_ok=True)
    print(f"LLDP文件将保存到: {local_directory}")
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Generate filename once to ensure consistency
            lldp_filename = process_hostname_for_lldp(device['hostname'], args)
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Get command based on arguments using the generated filename
            command = get_lldp_command_by_args(args, device['hostname'], lldp_filename)
            
            # Determine if we need cli -c wrapper based on username
            if username.lower() == 'root':
                full_command = f"cli -c '{command}'"
                print(f"执行命令: {full_command}")
            else:
                full_command = command
                print(f"执行命令: {full_command}")
            
            stdin, stdout, stderr = ssh.exec_command(full_command)
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功保存LLDP信息")
                
                # Use the same filename for download
                remote_file_path = f"/var/home/{username}/{lldp_filename}"
                local_file_path = os.path.join(local_directory, lldp_filename)
                
                print(f"正在从 {device['hostname']} 下载LLDP文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"LLDP文件已成功下载到 {local_file_path}")
                
                # Create backup copy if requested
                if args.backup:
                    create_backup_copy(local_file_path, 'lldp')
            else:
                print(f"在 {device['hostname']} 上执行LLDP命令时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # Close SSH connection
            ssh.close()
            
        except Exception as e:
            print(f"连接 {device['hostname']} 时出错: {str(e)}")
            continue

def get_mac_table_time_based_directory(base_dir):
    """Get the time-based subdirectory for storing mac-table files"""
    now = datetime.now()
    time_subdir = now.strftime("%Y%m%d")
    return os.path.join(base_dir, time_subdir)

def process_hostname_for_mac_table(hostname, args):
    """Remove '_re' suffix from hostname and add mac-table suffix with optional date/time"""
    # Remove '_re' suffix if present
    if hostname.endswith('_re'):
        base_name = hostname[:-3]
    else:
        base_name = hostname
    
    # Add date and time only if requested
    date_time_suffix = ""
    if args.date or args.time:
        now = datetime.now()
        if args.date:
            date_time_suffix += "-" + now.strftime("%Y%m%d")
        if args.time:
            date_time_suffix += "-" + now.strftime("%H%M%S")
    
    # Construct final filename
    filename = f"{base_name}-mac-table{date_time_suffix}.txt"
    return filename

def detect_device_type(ssh, username):
    """Detect if device is router or switch by checking version mode"""
    try:
        # Execute show version | grep mode to get device mode
        if username.lower() == 'root':
            version_command = "cli -c 'show version | grep mode'"
        else:
            version_command = "show version | grep mode"
        
        stdin, stdout, stderr = ssh.exec_command(version_command)
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status == 0:
            output = stdout.read().decode().strip().lower()
            print(f"设备模式信息: {output}")
            
            # Check if device is router (mx or ptx in mode)
            if 'mx' in output or 'ptx' in output:
                return 'router'
            # Check if device is switch (qfx or ex in mode)
            elif 'qfx' in output or 'ex' in output:
                return 'switch'
            else:
                print("警告: 无法确定设备类型，默认使用交换机命令")
                return 'switch'  # Default to switch
        else:
            print("警告: 无法获取设备版本信息，默认使用交换机命令")
            return 'switch'  # Default to switch
    except Exception as e:
        print(f"检测设备类型时出错: {str(e)}，默认使用交换机命令")
        return 'switch'  # Default to switch

def get_mac_table_command_by_args(args, hostname, filename, device_type):
    """Get the appropriate mac-table command based on device type and command line arguments"""
    # Build the command based on device type
    if device_type == 'router':
        command = "show bridge mac-table"
        print(f"检测到路由器设备，使用命令: {command}")
    else:  # switch
        command = "show ethernet-switching table"
        print(f"检测到交换机设备，使用命令: {command}")
    
    command += f" | save {filename}"
    return command

def get_mac_table_save_directory():
    """Get mac-table save directory from user input with default"""
    default_dir = os.path.expanduser('~/tesla-op/mac-table')
    print(f"\n请指定MAC表文件保存目录:")
    
    user_input = input(f"保存目录 [默认: {default_dir}]: ").strip()
    
    if user_input:
        # User specified a directory
        base_dir = os.path.expanduser(user_input)
    else:
        # Use default directory
        base_dir = default_dir
    
    return base_dir

def get_mac_table_mode_description(args):
    """Get description of the selected mac-table mode"""
    description_parts = ["MAC table mode"]
    
    # Add date/time/backup options to description
    options = []
    if args.date:
        options.append("date")
    if args.time:
        options.append("time")
    if args.backup:
        options.append("backup")
    
    if options:
        description_parts.append(f"with {' and '.join(options)} enabled")
    
    return ", ".join(description_parts)

def handle_mac_table_command(args):
    """Handle the mac-table subcommand"""
    # Get device information from user
    devices = get_device_info()
    
    if not devices:
        print("未输入任何设备信息，程序退出。")
        return
    
    # Get credentials from user
    username, password = get_credentials()
    
    # Get save directory from user
    base_save_dir = get_mac_table_save_directory()
    
    # Show selected mode
    mode_description = get_mac_table_mode_description(args)
    print(f"选择模式: {mode_description}")
    print(f"共输入 {len(devices)} 台设备，开始处理...")
    
    # Create time-based local directory if it doesn't exist
    local_directory = get_mac_table_time_based_directory(base_save_dir)
    os.makedirs(local_directory, exist_ok=True)
    print(f"MAC表文件将保存到: {local_directory}")
    
    for device in devices:
        try:
            print(f"正在连接 {device['hostname']} ({device['ip']})...")
            
            # Generate filename once to ensure consistency
            mac_table_filename = process_hostname_for_mac_table(device['hostname'], args)
            
            # Create SSH connection
            ssh = create_ssh_client()
            ssh.connect(
                hostname=device['ip'],
                username=username,
                password=password,
                timeout=10
            )
            
            # Detect device type (router or switch)
            device_type = detect_device_type(ssh, username)
            
            # Get command based on device type and arguments using the generated filename
            command = get_mac_table_command_by_args(args, device['hostname'], mac_table_filename, device_type)
            
            # Determine if we need cli -c wrapper based on username
            if username.lower() == 'root':
                full_command = f"cli -c '{command}'"
                print(f"执行命令: {full_command}")
            else:
                full_command = command
                print(f"执行命令: {full_command}")
            
            stdin, stdout, stderr = ssh.exec_command(full_command)
            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            
            if exit_status == 0:
                print(f"在 {device['hostname']} 上成功保存MAC表信息")
                
                # Use the same filename for download
                remote_file_path = f"/var/home/{username}/{mac_table_filename}"
                local_file_path = os.path.join(local_directory, mac_table_filename)
                
                print(f"正在从 {device['hostname']} 下载MAC表文件...")
                download_file(ssh, remote_file_path, local_file_path)
                print(f"MAC表文件已成功下载到 {local_file_path}")
                
                # Create backup copy if requested
                if args.backup:
                    create_backup_copy(local_file_path, 'mac-table')
            else:
                print(f"在 {device['hostname']} 上执行MAC表命令时出错")
                error_output = stderr.read().decode()
                if error_output:
                    print(error_output)
            
            # Close SSH connection
            ssh.close()
            
        except Exception as e:
            print(f"连接 {device['hostname']} 时出错: {str(e)}")
            continue

def create_backup_copy(local_file_path, backup_category):
    """Create a backup copy of the file in ~/tesla-op/backup/{category} directory"""
    try:
        # Get current date for backup subdirectory
        now = datetime.now()
        backup_date = now.strftime("%Y%m%d")
        
        # Create backup directory structure
        backup_base_dir = os.path.expanduser('~/tesla-op/backup')
        backup_category_dir = os.path.join(backup_base_dir, backup_category)
        backup_dir = os.path.join(backup_category_dir, backup_date)
        
        # Create directories if they don't exist
        os.makedirs(backup_dir, exist_ok=True)
        
        # Get filename from local file path
        filename = os.path.basename(local_file_path)
        backup_file_path = os.path.join(backup_dir, filename)
        
        # Copy file to backup location
        import shutil
        shutil.copy2(local_file_path, backup_file_path)
        
        print(f"备份文件已创建: {backup_file_path}")
        return True
        
    except Exception as e:
        print(f"创建备份文件时出错: {str(e)}")
        return False

if __name__ == "__main__":
    main()