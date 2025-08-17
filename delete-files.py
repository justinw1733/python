#!/usr/bin/env python3
"""
删除指定目录及其子目录中同名文件的脚本
"""

import os
import argparse
from pathlib import Path

def delete_files_in_directory(directory, filenames, dry_run=False):
    """
    删除指定目录及其所有子目录中具有指定名称的文件
    
    参数:
        directory (str): 要搜索的根目录
        filenames (list): 要删除的文件名列表
        dry_run (bool): 如果为True,则只显示将要删除的内容而不实际删除
    
    返回:
        int: 删除的文件数量
    """
    deleted_count = 0
    
    # 转换为Path对象以便于处理
    root_path = Path(directory)
    
    # 检查目录是否存在
    if not root_path.exists():
        print(f"错误: 目录 '{directory}' 不存在")
        return deleted_count
    
    if not root_path.is_dir():
        print(f"错误: '{directory}' 不是一个目录")
        return deleted_count
    
    # 遍历所有子目录，对每个文件名进行处理
    for filename in filenames:
        for file_path in root_path.rglob(f"**/{filename}"):
            if file_path.is_file():
                try:
                    if dry_run:
                        print(f"将删除: {file_path}")
                    else:
                        file_path.unlink()
                        print(f"已删除: {file_path}")
                    deleted_count += 1
                except Exception as e:
                    print(f"删除 {file_path} 时出错: {e}")
    
    if deleted_count == 0:
        print(f"在 '{directory}' 及其子目录中未找到指定的文件")
    else:
        action = "将删除" if dry_run else "已删除"
        print(f"{action} {deleted_count} 个文件")
    
    return deleted_count

def main():
    parser = argparse.ArgumentParser(description="删除指定目录及其子目录中具有指定名称的文件")
    parser.add_argument("directory", help="要搜索的根目录")
    parser.add_argument("filenames", nargs='+', help="要删除的文件名(可指定多个)")
    parser.add_argument("--dry-run", action="store_true", 
                        help="预览将要删除的内容而不实际删除")
    
    args = parser.parse_args()
    
    delete_files_in_directory(args.directory, args.filenames, args.dry_run)

if __name__ == "__main__":
    main()