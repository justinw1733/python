#!/usr/bin/env python3
"""
删除指定目录及其子目录中同名文件的脚本

优化功能:
- 支持通配符模式匹配
- 批量删除优化
- 进度指示器
- 彩色输出
- 文件大小统计
- 安全确认提示
- 详细日志记录
- 排除特定目录
"""

import os
import sys
import time
import fnmatch
import argparse
from pathlib import Path
from typing import List, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class Colors:
    """终端颜色代码"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def setup_logging(verbose: bool = False) -> None:
    """设置日志配置"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('delete_files.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def get_file_size_str(size_bytes: int) -> str:
    """将字节大小转换为可读的格式"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.1f} {size_names[i]}"


def print_colored(text: str, color: str = Colors.WHITE) -> None:
    """打印彩色文本"""
    print(f"{color}{text}{Colors.END}")


def confirm_deletion(file_count: int, total_size: int) -> bool:
    """确认删除操作"""
    size_str = get_file_size_str(total_size)
    print_colored(f"\n警告: 将删除 {file_count} 个文件，总大小: {size_str}", Colors.YELLOW)
    while True:
        response = input("确认删除? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no', '']:
            return False
        else:
            print("请输入 'y' 或 'n'")


def find_matching_files(root_path: Path, patterns: List[str], 
                       exclude_dirs: Optional[Set[str]] = None) -> List[Tuple[Path, int]]:
    """查找匹配的文件
    
    参数:
        root_path: 根目录路径
        patterns: 文件名模式列表（支持通配符）
        exclude_dirs: 要排除的目录名集合
    
    返回:
        匹配文件的路径和大小的元组列表
    """
    if exclude_dirs is None:
        exclude_dirs = set()
    
    matching_files = []
    total_files = 0
    
    print_colored("正在扫描文件...", Colors.CYAN)
    
    for file_path in root_path.rglob("*"):
        if file_path.is_file():
            total_files += 1
            if total_files % 1000 == 0:
                print(f"\r已扫描 {total_files} 个文件...", end="", flush=True)
            
            # 检查是否在排除目录中
            if any(excluded_dir in file_path.parts for excluded_dir in exclude_dirs):
                continue
                
            # 检查文件名是否匹配任何模式
            filename = file_path.name
            for pattern in patterns:
                if fnmatch.fnmatch(filename, pattern):
                    try:
                        file_size = file_path.stat().st_size
                        matching_files.append((file_path, file_size))
                        break
                    except OSError as e:
                        logging.warning(f"无法获取文件 {file_path} 的信息: {e}")
    
    print(f"\r已扫描 {total_files} 个文件，找到 {len(matching_files)} 个匹配文件")
    return matching_files


def delete_file_batch(files_batch: List[Tuple[Path, int]], dry_run: bool = False) -> Tuple[int, int, int]:
    """批量删除文件
    
    返回:
        (成功删除数, 失败数, 删除的总字节数)
    """
    success_count = 0
    error_count = 0
    total_bytes = 0
    
    for file_path, file_size in files_batch:
        try:
            if dry_run:
                print_colored(f"[预览] 将删除: {file_path} ({get_file_size_str(file_size)})", Colors.YELLOW)
                success_count += 1
                total_bytes += file_size
            else:
                file_path.unlink()
                print_colored(f"[删除] {file_path} ({get_file_size_str(file_size)})", Colors.GREEN)
                success_count += 1
                total_bytes += file_size
                logging.info(f"已删除文件: {file_path}")
        except Exception as e:
            print_colored(f"[错误] 删除 {file_path} 失败: {e}", Colors.RED)
            logging.error(f"删除 {file_path} 时出错: {e}")
            error_count += 1
    
    return success_count, error_count, total_bytes


def delete_files_in_directory(directory: str, patterns: List[str], 
                             dry_run: bool = False, 
                             batch_size: int = 100,
                             exclude_dirs: Optional[List[str]] = None,
                             require_confirmation: bool = True,
                             max_workers: int = 4) -> dict:
    """删除指定目录及其所有子目录中匹配模式的文件
    
    参数:
        directory: 要搜索的根目录
        patterns: 要删除的文件名模式列表（支持通配符）
        dry_run: 如果为True,则只显示将要删除的内容而不实际删除
        batch_size: 批处理大小
        exclude_dirs: 要排除的目录列表
        require_confirmation: 是否需要用户确认
        max_workers: 最大并行工作线程数
    
    返回:
        包含操作结果的字典
    """
    result = {
        'deleted_count': 0,
        'error_count': 0,
        'total_size': 0,
        'files_found': 0
    }
    
    # 转换为Path对象以便于处理
    root_path = Path(directory).resolve()
    
    # 检查目录是否存在
    if not root_path.exists():
        print_colored(f"错误: 目录 '{directory}' 不存在", Colors.RED)
        return result
    
    if not root_path.is_dir():
        print_colored(f"错误: '{directory}' 不是一个目录", Colors.RED)
        return result
    
    exclude_set = set(exclude_dirs) if exclude_dirs else set()
    
    print_colored(f"\n开始处理目录: {root_path}", Colors.BLUE)
    print_colored(f"搜索模式: {', '.join(patterns)}", Colors.BLUE)
    if exclude_set:
        print_colored(f"排除目录: {', '.join(exclude_set)}", Colors.BLUE)
    
    # 查找匹配的文件
    start_time = time.time()
    matching_files = find_matching_files(root_path, patterns, exclude_set)
    scan_time = time.time() - start_time
    
    result['files_found'] = len(matching_files)
    
    if not matching_files:
        print_colored(f"\n在 '{directory}' 及其子目录中未找到匹配的文件", Colors.YELLOW)
        return result
    
    # 计算总大小
    total_size = sum(size for _, size in matching_files)
    result['total_size'] = total_size
    
    print_colored(f"\n找到 {len(matching_files)} 个匹配文件，总大小: {get_file_size_str(total_size)}", Colors.CYAN)
    print_colored(f"扫描耗时: {scan_time:.2f} 秒", Colors.CYAN)
    
    # 如果不是预览模式且需要确认，则请求用户确认
    if not dry_run and require_confirmation:
        if not confirm_deletion(len(matching_files), total_size):
            print_colored("操作已取消", Colors.YELLOW)
            return result
    
    # 批量处理文件
    print_colored(f"\n开始{'预览' if dry_run else '删除'}文件...", Colors.BLUE)
    
    total_deleted = 0
    total_errors = 0
    total_bytes_processed = 0
    
    # 将文件分批处理
    batches = [matching_files[i:i + batch_size] for i in range(0, len(matching_files), batch_size)]
    
    if max_workers > 1 and len(batches) > 1:
        # 使用多线程处理批次
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_batch = {executor.submit(delete_file_batch, batch, dry_run): batch 
                             for batch in batches}
            
            for i, future in enumerate(as_completed(future_to_batch)):
                try:
                    success, errors, bytes_processed = future.result()
                    total_deleted += success
                    total_errors += errors
                    total_bytes_processed += bytes_processed
                    
                    progress = ((i + 1) / len(batches)) * 100
                    print(f"\r进度: {progress:.1f}% ({total_deleted}/{len(matching_files)})", 
                          end="", flush=True)
                except Exception as e:
                    logging.error(f"批处理任务执行失败: {e}")
                    total_errors += len(future_to_batch[future])
    else:
        # 单线程处理
        for i, batch in enumerate(batches):
            success, errors, bytes_processed = delete_file_batch(batch, dry_run)
            total_deleted += success
            total_errors += errors
            total_bytes_processed += bytes_processed
            
            progress = ((i + 1) / len(batches)) * 100
            print(f"\r进度: {progress:.1f}% ({total_deleted}/{len(matching_files)})", 
                  end="", flush=True)
    
    print()  # 换行
    
    result['deleted_count'] = total_deleted
    result['error_count'] = total_errors
    
    # 显示结果摘要
    action = "预览" if dry_run else "删除"
    if total_deleted > 0:
        print_colored(f"\n✓ 成功{action} {total_deleted} 个文件", Colors.GREEN)
        print_colored(f"  总大小: {get_file_size_str(total_bytes_processed)}", Colors.GREEN)
    
    if total_errors > 0:
        print_colored(f"✗ {total_errors} 个文件处理失败", Colors.RED)
    
    processing_time = time.time() - start_time
    print_colored(f"\n总耗时: {processing_time:.2f} 秒", Colors.CYAN)
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="删除指定目录及其子目录中匹配模式的文件",
        epilog="""示例:
  %(prog)s /path/to/dir "*.tmp" "*.log"        # 删除所有.tmp和.log文件
  %(prog)s /path/to/dir "test_*" --dry-run     # 预览删除所有test_开头的文件
  %(prog)s /path/to/dir "*.pyc" --exclude-dirs __pycache__ .git  # 删除.pyc文件，排除特定目录
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("directory", help="要搜索的根目录")
    parser.add_argument("patterns", nargs='+', 
                        help="要删除的文件名模式(支持通配符，可指定多个)")
    parser.add_argument("--dry-run", action="store_true", 
                        help="预览将要删除的内容而不实际删除")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="批处理大小 (默认: 100)")
    parser.add_argument("--exclude-dirs", nargs='*', default=[],
                        help="要排除的目录名列表")
    parser.add_argument("--no-confirm", action="store_true",
                        help="跳过删除确认提示")
    parser.add_argument("--max-workers", type=int, default=4,
                        help="最大并行工作线程数 (默认: 4)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="详细输出模式")
    
    args = parser.parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    try:
        result = delete_files_in_directory(
            directory=args.directory,
            patterns=args.patterns,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
            exclude_dirs=args.exclude_dirs,
            require_confirmation=not args.no_confirm,
            max_workers=args.max_workers
        )
        
        # 根据结果设置退出代码
        if result['error_count'] > 0:
            sys.exit(1)
        elif result['deleted_count'] == 0 and result['files_found'] == 0:
            sys.exit(2)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print_colored("\n操作被用户中断", Colors.YELLOW)
        sys.exit(130)
    except Exception as e:
        print_colored(f"发生意外错误: {e}", Colors.RED)
        logging.error(f"意外错误: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()