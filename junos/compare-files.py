#!/usr/bin/env python3
import sys
import os
import glob
from collections import defaultdict

def read_config_file(filepath):
    """读取配置文件内容"""
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        # 过滤空行和注释行
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"文件 {filepath} 未找到")
        return []

def parse_config_lines(lines):
    """解析配置行，提取第一层级和其他信息"""
    parsed_lines = []
    for line in lines:
        if line.startswith('set '):
            # 提取第一层级
            parts = line.split()
            if len(parts) >= 2:
                # 第一层级通常是"set"后的第一个关键词
                first_level = parts[1]
                parsed_lines.append({
                    'full_line': line,
                    'first_level': first_level,
                    'rest': ' '.join(parts[2:]) if len(parts) > 2 else ''
                })
    return parsed_lines

def get_first_level_category(first_level):
    """根据第一层级关键词分类"""
    category_mapping = {
        'system': 'System',
        'interfaces': 'Interfaces',
        'protocols': 'Protocols',
        'routing-options': 'Routing Options',
        'vlans': 'VLANs',
        'policy-options': 'Policy Options',
        'firewall': 'Firewall',
        'class-of-service': 'Class of Service',
        'chassis': 'Chassis',
        'services': 'Services',
        'security': 'Security',
        'applications': 'Applications',
        'routing-instances': 'Routing Instances',
        'forwarding-options': 'Forwarding Options',
        'ethernet-switching': 'Ethernet Switching'
    }
    
    return category_mapping.get(first_level, first_level.capitalize())

def find_common_and_unique_configs(parsed_configs, filenames):
    """找出多个配置文件中的相同部分和各自独有的部分"""
    # 创建每个文件配置行的集合
    config_sets = []
    for parsed in parsed_configs:
        config_sets.append({item['full_line'] for item in parsed})
    
    # 找出所有配置行
    all_lines = set()
    for config_set in config_sets:
        all_lines.update(config_set)
    
    # 分析每行配置出现在哪些文件中
    line_occurrences = defaultdict(list)
    for i, config_set in enumerate(config_sets):
        for line in config_set:
            line_occurrences[line].append(i)
    
    # 分类配置行
    common_lines = []  # 出现在所有文件中的行
    unique_lines = [[] for _ in filenames]  # 每个文件独有的行
    partial_lines = []  # 出现在部分文件中的行
    
    for line, occurrences in line_occurrences.items():
        if len(occurrences) == len(filenames):
            # 出现在所有文件中
            common_lines.append(line)
        elif len(occurrences) == 1:
            # 仅出现在一个文件中
            file_index = occurrences[0]
            unique_lines[file_index].append((line, filenames[file_index]))
        else:
            # 出现在部分文件中
            file_names = [filenames[i] for i in occurrences]
            partial_lines.append((line, file_names))
    
    return common_lines, unique_lines, partial_lines

def group_by_first_level(lines, parsed_data=None):
    """按第一层级对配置行进行分组"""
    grouped = defaultdict(list)
    
    # 如果提供了解析数据，使用它来获取第一层级信息
    if parsed_data:
        line_to_first_level = {item['full_line']: item['first_level'] for item in parsed_data}
        for line in lines:
            first_level = line_to_first_level.get(line, 'unknown')
            category = get_first_level_category(first_level)
            grouped[category].append(line)
    else:
        # 否则直接解析行
        for line in lines:
            if line.startswith('set '):
                parts = line.split()
                if len(parts) >= 2:
                    first_level = parts[1]
                    category = get_first_level_category(first_level)
                    grouped[category].append(line)
                else:
                    grouped['Other'].append(line)
            else:
                grouped['Other'].append(line)
    
    return grouped

def get_txt_files_in_current_directory():
    """获取当前目录下的所有.txt文件"""
    txt_files = glob.glob("*.txt")
    return sorted(txt_files)

def main():
    # 检查命令行参数
    if len(sys.argv) == 1:
        # 没有参数，使用当前目录的所有.txt文件
        file_paths = get_txt_files_in_current_directory()
        if not file_paths:
            print("当前目录下没有找到.txt文件")
            sys.exit(1)
        elif len(file_paths) < 2:
            print("当前目录下.txt文件少于2个，无法进行比较")
            sys.exit(1)
        print(f"未指定文件参数，将比较当前目录下的所有.txt文件: {', '.join(file_paths)}")
    elif len(sys.argv) == 2:
        print("使用方法: python Compare-files.py [文件1] [文件2] [文件3] ...")
        print("例如: python Compare-files.py vqfx1_re.txt vqfx2_re.txt")
        print("例如: python Compare-files.py file1.txt file2.txt file3.txt")
        print("注意: 至少需要指定2个文件进行比较")
        sys.exit(1)
    else:
        # 有参数，使用指定的文件
        file_paths = sys.argv[1:]
    
    filenames = [os.path.basename(path) for path in file_paths]
    
    # 检查文件是否存在
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"配置文件 {file_path} 不存在")
            sys.exit(1)
    
    # 读取所有配置文件
    all_config_lines = []
    all_parsed_configs = []
    
    for file_path in file_paths:
        config_lines = read_config_file(file_path)
        if not config_lines:
            print(f"警告: 配置文件 {file_path} 内容为空或无法读取")
        all_config_lines.append(config_lines)
        all_parsed_configs.append(parse_config_lines(config_lines))
    
    # 分析配置文件
    common_lines, unique_lines, partial_lines = find_common_and_unique_configs(all_parsed_configs, filenames)
    
    print(f"对比配置文件: {' 和 '.join(filenames)}")
    print("=" * 80)
    
    # 打印相同的部分
    if common_lines:
        print(f"\n【相同配置项】(出现在所有 {len(filenames)} 个文件中):")
        print("-" * 60)
        grouped_common = group_by_first_level(common_lines, all_parsed_configs[0])
        sorted_categories = sorted(grouped_common.keys())
        
        for category in sorted_categories:
            if grouped_common[category]:  # 只显示非空类别
                print(f"\n  {category}:")
                sorted_lines = sorted(grouped_common[category])
                for line in sorted_lines:
                    print(f"    {line}")
        print(f"\n  总共 {len(common_lines)} 个相同配置项")
    else:
        print(f"\n【相同配置项】: 无")
    
    # 打印部分相同的配置
    if partial_lines:
        print(f"\n【部分相同配置项】(出现在部分文件中):")
        print("-" * 60)
        
        # 按文件组合分组
        combination_groups = defaultdict(list)
        for line, file_names in partial_lines:
            combination_key = ', '.join(sorted(file_names))
            combination_groups[combination_key].append(line)
        
        for combination, lines in sorted(combination_groups.items()):
            print(f"\n  出现在 {combination} 中:")
            grouped_partial = group_by_first_level(lines, all_parsed_configs[0])
            sorted_categories = sorted(grouped_partial.keys())
            
            for category in sorted_categories:
                if grouped_partial[category]:  # 只显示非空类别
                    print(f"    {category}:")
                    sorted_lines = sorted(grouped_partial[category])
                    for line in sorted_lines:
                        print(f"      {line}")
        print(f"\n  总共 {len(partial_lines)} 个部分相同配置项")
    else:
        print(f"\n【部分相同配置项】: 无")
    
    # 打印每个文件独有的配置
    print(f"\n【各文件独有配置项】:")
    print("-" * 60)
    
    has_unique = False
    for i, file_unique_lines in enumerate(unique_lines):
        if file_unique_lines:
            has_unique = True
            print(f"\n  仅在 {filenames[i]} 中存在:")
            # 提取行内容用于分组
            lines_only = [line for line, _ in file_unique_lines]
            grouped_unique = group_by_first_level(lines_only, all_parsed_configs[i])
            sorted_categories = sorted(grouped_unique.keys())
            
            for category in sorted_categories:
                if grouped_unique[category]:  # 只显示非空类别
                    print(f"    {category}:")
                    sorted_lines = sorted(grouped_unique[category])
                    for line in sorted_lines:
                        print(f"      {line}")
            print(f"    总共 {len(file_unique_lines)} 个独有配置项")
    
    if not has_unique:
        print("  无")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()