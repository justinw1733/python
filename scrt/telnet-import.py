# $language = "Python"
# $interface = "1.0"

import os

# SecureCRT Sessions 目录（macOS 默认路径）
sessions_folder = os.path.expanduser("/Users/justinw/Library/Application Support/VanDyke/SecureCRT/Config/Sessions")
group_name = "Juniper-VMM-Pods"  # 你的分组目录名

# 批量定义 session 信息
# 定义相同的字段值
common_settings = {
    "port": "23",  # Telnet默认端口为23
    "username": "justinw",
    "protocol": "Telnet",
}

# 定义主机名列表
hostnames = [
    "elpod1-vmm.englab.juniper.net",
    "elpod2-vmm.englab.juniper.net",
    "elpod3-vmm.englab.juniper.net",
    "enpod2-vmm.englab.juniper.net",
    "enpod4-vmm.englab.juniper.net",
    "enpod6-vmm.englab.juniper.net",
    "enpod7-vmm.englab.juniper.net",
    # 更多主机...
]

# 使用循环生成会话列表
sessions = [
    {
        "hostname": hostname,
        "name": hostname.replace(".englab.juniper.net", ""),  # 自动生成 name 字段
        **common_settings
    }
    for hostname in hostnames
]

def create_session(session):
    session_path = os.path.join(sessions_folder, group_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
    ini_filename = f"{session['name']}.ini"
    ini_path = os.path.join(session_path, ini_filename)
    with open(ini_path, "w") as f:
        f.write(f"""S:"Session Name"={session['hostname']}
S:"Hostname"={session['hostname']}
S:"Username"={session['username']}
S:"Protocol Name"={session['protocol']}
D:"Port"={session['port']}
S:"Password"=Embe1mpls  # 这里替换为实际的密码
""")



def main():
    for session in sessions:
        create_session(session)
if __name__ == "__main__":
    main()