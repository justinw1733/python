#!/usr/bin/env python3
# $language = "Python"
# $interface = "1.0"

import os

# SecureCRT Sessions 目录（macOS 默认路径）
sessions_folder = os.path.expanduser("/Users/justinw/Library/Application Support/VanDyke/SecureCRT/Config/Sessions")

# 批量定义 session 信息
# 定义相同的字段值
common_settings = {
    "port": "22",
    "protocol": "SSH2",
    "username": "root",
    "password": "Embe1mpls"
}

def parse_hosts_input(hosts_text):
    """
    解析输入的主机信息文本
    格式: session_name ip_address
    """
    sessions = []
    lines = hosts_text.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:  # 跳过空行
            continue
            
        parts = line.split()
        if len(parts) >= 2:
            session_name = parts[0]
            hostname = parts[1]
            
            session = {
                "name": session_name,
                "hostname": hostname,
                "username": common_settings["username"],
                "password": common_settings["password"],
                "port": common_settings["port"],
                "protocol": common_settings["protocol"]
            }
            sessions.append(session)
        else:
            print(f"警告: 无法解析行 '{line}'，请确保格式为 'session_name ip_address'")
    
    return sessions

def create_session(session, group_name):
    """
    创建单个会话文件,包含自动执行cli命令的设置
    """
    # 创建会话目录（如果不存在）
    session_path = os.path.join(sessions_folder, group_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
    
    # 创建 .ini 文件
    ini_filename = f"{session['name']}.ini"
    ini_path = os.path.join(session_path, ini_filename)
    
    with open(ini_path, "w") as f:
        f.write(f"""S:"Session Name"={session['hostname']}
S:"Hostname"={session['hostname']}
S:"Username"={session['username']}
S:"Protocol Name"={session['protocol']}
D:"Port"={session['port']}
S:"Password"={session['password']}
S:"Password Saved"=00000001
S:"Initial Terminal Shell Command"=cli
""")

def main():
    # Prompt for group name
    group_name = input("请输入分组目录名: ").strip()
    if not group_name:
        print("错误: 分组目录名不能为空")
        return
    
    print("请输入主机信息，格式为每行一个 '会话名称 IP地址'")
    print("例如:")
    print("vmx1_re 10.207.202.191")
    print("vmx2_re 10.207.200.184")
    print("输入完成后，请在新行按 Ctrl+D (Mac/Linux) 或 Ctrl+Z 然后回车 (Windows)")
    
    # 读取多行输入
    hosts_input = ""
    try:
        while True:
            line = input()
            hosts_input += line + "\n"
    except EOFError:
        pass  # Ctrl+D 或 Ctrl+Z 结束输入
    
    # 解析输入的主机信息
    sessions = parse_hosts_input(hosts_input)
    
    # 创建所有会话
    for session in sessions:
        create_session(session, group_name)
        print(f"已创建会话: {session['name']} -> {session['hostname']}")
    
    print(f"总共创建了 {len(sessions)} 个会话")

if __name__ == "__main__":
    main()