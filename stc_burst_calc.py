#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Spirent STC 突发流量参数计算器

运行方法：
  1. 命令行参数模式 (完整参数):
    python3 stc_burst_calc.py --avg-rate 4G --burst-rate 10G --frame-size 1518 --bursts-per-sec 100

  2. 命令行参数模式 (简化参数):
    python3 stc_burst_calc.py -ar 4G -br 10G -fr 1518 -bs 100

  3. 交互式输入模式:
    python3 stc_burst_calc.py
    (不带任何参数运行即可进入交互式模式)

或者在 Unix/Linux/macOS 系统上确保脚本有执行权限后：
  ./stc_burst_calc.py -ar 4G -br 10G -fr 1518 -bs 100

如果直接运行遇到问题，请使用第一种方法（显式调用 python3）。

输入参数：
- 平均速率 (支持 G/M/K 单位，例如 4G, 4000M, 4000000K)
- 突发速率 (支持 G/M/K 单位，例如 10G, 10000M, 10000000K)
- 帧大小 (字节) —— 完整帧大小，包括 L2 头、FCS 和可能的 VLAN 标签（例如 1518）
- 每秒突发次数 (bursts_per_sec)

默认算法包含以太网头/CRC和前导码+IFG到“在线比特数”的计算

输出：
- 突发帧数 (Burst Size，帧/次) - 四舍五入为整数显示
- 发送时间 (秒)
- 周期时间 (秒)
- 空闲时间 (秒)

说明：
- 如果以太网开销计算开启：在线帧比特 = (完整帧大小) * 8 (+ preamble + IFG)
- 默认包含 L2 头(14) + FCS(4)
- 默认包含 Preamble(8) + SFD(1) + IFG(12) = 21 字节
- 用户应输入完整帧大小，包括任何 VLAN 标签
"""

from dataclasses import dataclass
from typing import Optional
import argparse


@dataclass
class BurstParams:
    burst_size_frames: float  # 每次突发发送的帧数（可能是非整数；实际配置通常取整）
    send_time_s: float        # 每次突发的发送时间（秒）
    cycle_time_s: float       # 每次突发的总周期（秒）
    idle_time_s: float        # 每次突发的空闲时间（秒）


def compute_frame_bits(frame_size_bytes: int) -> int:
    """
    计算在线上占用的比特数（包含以太网开销以及前导码/IFG）

    :param frame_size_bytes: 完整帧大小（字节），包括可能的VLAN标签
    :return: 每帧在线比特数
    """
    # 用户输入的是完整帧大小，直接使用
    on_wire_frame_bytes = frame_size_bytes
    
    # 包含 Preamble + IFG（20 字节）
    preamble_ifg_bytes = 20

    total_bytes_on_wire_per_frame = on_wire_frame_bytes + preamble_ifg_bytes
    return total_bytes_on_wire_per_frame * 8  # bits


def calculate_burst_by_bps(avg_rate_gbps: float,
                           burst_rate_gbps: float,
                           frame_size_bytes: int,
                           bursts_per_second: float) -> BurstParams:
    """
    根据每秒突发次数计算突发参数。

    :param avg_rate_gbps: 平均速率（Gbps），例如 4
    :param burst_rate_gbps: 突发时的发送速率（Gbps），例如 10
    :param frame_size_bytes: 完整帧大小（字节），包括可能的VLAN标签
    :param bursts_per_second: 每秒突发次数，例如 100
    :return: BurstParams
    """
    if avg_rate_gbps <= 0:
        raise ValueError("平均速率必须为正数。")
    if burst_rate_gbps <= 0:
        raise ValueError("突发速率必须为正数。")
    if bursts_per_second <= 0:
        raise ValueError("每秒突发次数必须为正数。")
    if frame_size_bytes <= 0:
        raise ValueError("帧大小必须为正数。")

    frame_bits = compute_frame_bits(frame_size_bytes)

    cycle_time = 1.0 / bursts_per_second  # 每次突发周期（秒）
    bits_per_cycle = avg_rate_gbps * 1e9 * cycle_time  # 每次突发应发送的总比特数（按平均速率）

    burst_size_frames = bits_per_cycle / frame_bits  # 每次突发的帧数（可为小数）
    send_time = (burst_size_frames * frame_bits) / (burst_rate_gbps * 1e9)  # 突发发送时间（秒）
    idle_time = cycle_time - send_time
    if idle_time < 0:
        # 如果 idle_time 为负，说明设定的 bursts_per_second 太高或 burst_rate 太低导致不可实现
        raise ValueError("计算得到的空闲时间为负，检查突发次数/突发速率/平均速率设置是否合理。")

    return BurstParams(
        burst_size_frames=burst_size_frames,
        send_time_s=send_time,
        cycle_time_s=cycle_time,
        idle_time_s=idle_time
    )


def parse_rate_with_unit(rate_str: str) -> float:
    """
    解析带单位的速率字符串，如 "4G", "4M", "4K" 等
    返回以 Gbps 为单位的浮点数
    """
    rate_str = rate_str.strip().upper()
    
    if rate_str.endswith('G'):
        return float(rate_str[:-1])
    elif rate_str.endswith('M'):
        return float(rate_str[:-1]) / 1000
    elif rate_str.endswith('K'):
        return float(rate_str[:-1]) / 1000000
    else:
        # Assume it's already in Gbps if no unit specified
        return float(rate_str)


def rate_type(value):
    """
    用于 argparse 的自定义类型，解析带单位的速率
    """
    try:
        return parse_rate_with_unit(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"无效的速率值: {value}")


def format_params(params: BurstParams) -> str:
    """
    格式化输出结果。将突发帧数四舍五入为整数以便在 STC 中配置。
    """
    burst_size_str = f"{params.burst_size_frames:.3f} (≈ {int(round(params.burst_size_frames))} 帧)"

    return (
        "突发参数计算结果：\n"
        f"  突发帧数 (Burst Size): {burst_size_str}\n"
        f"  发送时间 (秒):         {params.send_time_s:.6f}\n"
        f"  周期时间 (秒):         {params.cycle_time_s:.6f}\n"
        f"  空闲时间 (秒):         {params.idle_time_s:.6f}\n"
    )




def get_interactive_params():
    """
    通过交互式提示获取参数
    """
    print("Spirent STC 突发流量参数计算器 - 交互式模式")
    print("=" * 50)
    
    try:
        avg_rate_input = input("请输入平均速率，支持单位 G/M/K [例如 4G, 4000M, 4000000K]: ")
        avg_rate = parse_rate_with_unit(avg_rate_input)
        
        burst_rate_input = input("请输入突发速率，支持单位 G/M/K [例如 10G, 10000M, 10000000K]: ")
        burst_rate = parse_rate_with_unit(burst_rate_input)
        
        frame_size = int(input("请输入完整帧大小 (字节) [例如 1518，包含 L2 头、FCS 和可能的 VLAN 标签]: "))
        bursts_per_sec = float(input("请输入每秒突发次数 [例如 100]: "))
        
        return {
            'avg_rate': avg_rate,
            'burst_rate': burst_rate,
            'frame_size': frame_size,
            'bursts_per_sec': bursts_per_sec
        }
    except ValueError as e:
        print(f"输入格式错误: {e}")
        return None
    except KeyboardInterrupt:
        print("\n用户取消操作")
        return None


def main():
    import sys
    
    # 检查是否有命令行参数
    if len(sys.argv) > 1:
        # 使用命令行参数模式
        parser = argparse.ArgumentParser(
            description="Spirent STC 突发流量参数计算器（按每秒突发次数模式）"
        )
        parser.add_argument("-ar", "--avg-rate", type=rate_type, required=True,
                            help="平均速率，支持单位 G/M/K，例如 4G, 4000M, 4000000K")
        parser.add_argument("-br", "--burst-rate", type=rate_type, required=True,
                            help="突发速率，支持单位 G/M/K，例如 10G, 10000M, 10000000K")
        parser.add_argument("-fr", "--frame-size", type=int, required=True,
                            help="完整帧大小 (字节)，例如 1518（包含 L2 头、FCS 和可能的 VLAN 标签）")
        parser.add_argument("-bs", "--bursts-per-sec", type=float, required=True,
                            help="每秒突发次数，例如 100")
        args = parser.parse_args()

        # 使用固定的默认值：包含 L2 头/FCS 和 Preamble+IFG
        params = calculate_burst_by_bps(
            avg_rate_gbps=args.avg_rate,
            burst_rate_gbps=args.burst_rate,
            frame_size_bytes=args.frame_size,
            bursts_per_second=args.bursts_per_sec
        )

        print(format_params(params))
    else:
        # 使用交互式输入模式
        params_dict = get_interactive_params()
        if params_dict is not None:
            params = calculate_burst_by_bps(
                avg_rate_gbps=params_dict['avg_rate'],
                burst_rate_gbps=params_dict['burst_rate'],
                frame_size_bytes=params_dict['frame_size'],
                bursts_per_second=params_dict['bursts_per_sec']
            )
            
            print(format_params(params))


if __name__ == "__main__":
    main()
