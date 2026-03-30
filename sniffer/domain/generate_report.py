#!/usr/bin/env python3
"""
生成CSV报告脚本
从test_model.py的输出和conn.log文件中提取统计信息，生成CSV格式的报告
"""

import json
import os
import sys
import csv
import subprocess
from pathlib import Path
from collections import defaultdict

def load_predictions(pred_file):
    """加载test_model.py的输出结果"""
    predictions = {}
    if not os.path.exists(pred_file):
        return predictions
    
    with open(pred_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or ',' not in line:
                continue
            parts = line.split(',', 1)
            if len(parts) == 2:
                flow_name, label = parts
                predictions[flow_name] = label
    
    return predictions

def aggregate_flow_stats(flow_dir, features_dir):
    """聚合一个流的所有conn.log记录的统计信息"""
    # 查找conn.log文件
    conn_log_paths = list(flow_dir.rglob("conn.log"))
    
    if not conn_log_paths:
        return None
    
    total_packets_sent = 0
    total_packets_recv = 0
    total_bytes_sent = 0
    total_bytes_recv = 0
    connections = set()
    timestamps = []
    
    for conn_log_path in conn_log_paths:
        if not os.path.exists(conn_log_path):
            continue
        
        with open(conn_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # 统计数据包和字节
                total_packets_sent += data.get('up_pkts', 0)
                total_packets_recv += data.get('down_pkts', 0)
                total_bytes_sent += data.get('up_bytes', 0)
                total_bytes_recv += data.get('down_bytes', 0)
                
                # 统计连接数（使用uid作为唯一标识）
                uid = data.get('uid', '')
                if uid:
                    connections.add(uid)
                
                # 收集时间戳
                ts = data.get('ts', 0)
                if ts > 0:
                    timestamps.append(ts)
    
    if not timestamps:
        return None
    
    return {
        'packets_sent': total_packets_sent,
        'packets_recv': total_packets_recv,
        'bytes_sent': total_bytes_sent,
        'bytes_recv': total_bytes_recv,
        'connections': len(connections),
        'first_seen': min(timestamps),
        'last_seen': max(timestamps)
    }

def format_timestamp(ts):
    """格式化时间戳为可读格式"""
    from datetime import datetime
    try:
        dt = datetime.fromtimestamp(ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def extract_stats_from_pcap(pcap_file):
    """从pcap文件中提取统计信息"""
    try:
        # 使用tshark提取统计信息
        # 获取数据包数量和时间信息
        cmd = ['tshark', '-r', str(pcap_file), '-q', '-z', 'conv,tcp']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # 如果tshark不可用，使用capinfos获取基本信息
        if result.returncode != 0:
            return extract_stats_from_pcap_capinfos(pcap_file)
        
        # 解析tshark输出
        lines = result.stdout.split('\n')
        total_packets_sent = 0
        total_packets_recv = 0
        total_bytes_sent = 0
        total_bytes_recv = 0
        connections = set()
        timestamps = []
        
        # 使用tshark提取数据包信息
        cmd2 = ['tshark', '-r', str(pcap_file), '-T', 'fields', 
                '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst', 
                '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'frame.len', '-e', 'frame.time_epoch']
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
        
        if result2.returncode == 0:
            # 假设第一个IP是源IP（需要根据实际情况调整）
            # 这里简化处理，使用capinfos方法
            return extract_stats_from_pcap_capinfos(pcap_file)
        
        return None
    except Exception as e:
        # 如果tshark失败，使用capinfos
        return extract_stats_from_pcap_capinfos(pcap_file)

def extract_stats_from_pcap_capinfos(pcap_file):
    """使用capinfos和tshark从pcap文件提取统计信息"""
    try:
        # 首先使用capinfos获取基本信息（不使用-M选项以获取时间信息）
        cmd = ['capinfos', '-c', '-S', '-u', str(pcap_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        stats = {
            'packets_sent': 0,
            'packets_recv': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'connections': 1,
            'first_seen': 0,
            'last_seen': 0
        }
        
        # 解析capinfos输出获取时间和数据包总数
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            total_packets = 0
            total_bytes = 0
            
            for line in lines:
                if 'Number of packets:' in line:
                    try:
                        total_packets = int(line.split(':')[1].strip())
                    except:
                        pass
                elif 'Data size:' in line:
                    try:
                        size_str = line.split(':')[1].strip().replace(',', '')
                        total_bytes = int(size_str.split()[0])
                    except:
                        pass
                elif 'First packet time:' in line:
                    try:
                        time_str = line.split(':', 1)[1].strip()
                        from datetime import datetime
                        # 处理带微秒的时间格式: "2020-06-12 16:45:32.019097"
                        if '.' in time_str:
                            time_part = time_str.split('.')[0]
                        else:
                            time_part = time_str
                        dt = datetime.strptime(time_part, '%Y-%m-%d %H:%M:%S')
                        stats['first_seen'] = dt.timestamp()
                    except Exception as e:
                        pass
                elif 'Last packet time:' in line:
                    try:
                        time_str = line.split(':', 1)[1].strip()
                        from datetime import datetime
                        # 处理带微秒的时间格式
                        if '.' in time_str:
                            time_part = time_str.split('.')[0]
                        else:
                            time_part = time_str
                        dt = datetime.strptime(time_part, '%Y-%m-%d %H:%M:%S')
                        stats['last_seen'] = dt.timestamp()
                    except Exception as e:
                        pass
        
        # 使用tshark提取方向性统计信息
        # 假设第一个数据包的源IP是"发送方"
        try:
            cmd2 = ['tshark', '-r', str(pcap_file), '-T', 'fields', 
                    '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len', '-e', 'frame.time_epoch']
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
            
            if result2.returncode == 0 and result2.stdout.strip():
                lines2 = result2.stdout.strip().split('\n')
                if lines2:
                    # 获取第一个数据包的源IP作为"发送方"
                    first_line = lines2[0].split('\t')
                    if len(first_line) >= 2:
                        sender_ip = first_line[0]
                        
                        packets_sent = 0
                        packets_recv = 0
                        bytes_sent = 0
                        bytes_recv = 0
                        
                        for line in lines2:
                            parts = line.split('\t')
                            if len(parts) >= 3:
                                src_ip = parts[0]
                                frame_len = int(parts[2]) if parts[2] else 0
                                
                                if src_ip == sender_ip:
                                    packets_sent += 1
                                    bytes_sent += frame_len
                                else:
                                    packets_recv += 1
                                    bytes_recv += frame_len
                        
                        stats['packets_sent'] = packets_sent
                        stats['packets_recv'] = packets_recv
                        stats['bytes_sent'] = bytes_sent
                        stats['bytes_recv'] = bytes_recv
                    else:
                        # 如果无法解析，使用总数的一半
                        stats['packets_sent'] = total_packets // 2
                        stats['packets_recv'] = total_packets - stats['packets_sent']
                        stats['bytes_sent'] = total_bytes // 2
                        stats['bytes_recv'] = total_bytes - stats['bytes_sent']
        except Exception as e:
            # 如果tshark失败，使用capinfos的总数
            stats['packets_sent'] = total_packets // 2
            stats['packets_recv'] = total_packets - stats['packets_sent']
            stats['bytes_sent'] = total_bytes // 2
            stats['bytes_recv'] = total_bytes - stats['bytes_sent']
        
        # 如果时间戳为0，使用tshark提取时间戳
        if stats['first_seen'] == 0 or stats['last_seen'] == 0:
            try:
                cmd_time = ['tshark', '-r', str(pcap_file), '-T', 'fields', '-e', 'frame.time_epoch']
                result_time = subprocess.run(cmd_time, capture_output=True, text=True, timeout=30)
                if result_time.returncode == 0 and result_time.stdout.strip():
                    timestamps = [float(ts) for ts in result_time.stdout.strip().split('\n') if ts.strip()]
                    if timestamps:
                        if stats['first_seen'] == 0:
                            stats['first_seen'] = min(timestamps)
                        if stats['last_seen'] == 0:
                            stats['last_seen'] = max(timestamps)
            except:
                pass
        
        # 如果时间戳仍为0，使用文件修改时间
        if stats['first_seen'] == 0:
            stats['first_seen'] = os.path.getmtime(pcap_file)
        if stats['last_seen'] == 0:
            stats['last_seen'] = os.path.getmtime(pcap_file)
        
        return stats
    except Exception as e:
        print(f"警告: 无法从pcap文件提取统计信息 {pcap_file}: {e}", file=sys.stderr)
        return None

def aggregate_classified_stats(classified_dir):
    """聚合classified目录下所有分类的统计信息"""
    classified_results = {}
    
    if not os.path.exists(classified_dir):
        return classified_results
    
    # 遍历classified目录下的所有子目录（分类类别）
    for category_dir in Path(classified_dir).iterdir():
        if not category_dir.is_dir():
            continue
        
        category_name = category_dir.name
        
        # 统计该类别下所有pcap文件
        pcap_files = list(category_dir.glob("*.pcap"))
        
        if not pcap_files:
            continue
        
        total_packets_sent = 0
        total_packets_recv = 0
        total_bytes_sent = 0
        total_bytes_recv = 0
        total_connections = 0
        timestamps = []
        
        for pcap_file in pcap_files:
            stats = extract_stats_from_pcap_capinfos(pcap_file)
            if stats:
                total_packets_sent += stats['packets_sent']
                total_packets_recv += stats['packets_recv']
                total_bytes_sent += stats['bytes_sent']
                total_bytes_recv += stats['bytes_recv']
                total_connections += stats['connections']
                if stats['first_seen'] > 0:
                    timestamps.append(stats['first_seen'])
                if stats['last_seen'] > 0:
                    timestamps.append(stats['last_seen'])
        
        if timestamps:
            classified_results[category_name] = {
                'packets_sent': total_packets_sent,
                'packets_recv': total_packets_recv,
                'bytes_sent': total_bytes_sent,
                'bytes_recv': total_bytes_recv,
                'connections': total_connections,
                'first_seen': min(timestamps),
                'last_seen': max(timestamps)
            }
    
    return classified_results

def load_existing_report(csv_path):
    """加载已有的 report.csv 文件"""
    existing_data = {}
    
    if not os.path.exists(csv_path):
        return existing_data
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row.get('app_name'):
                    continue
                
                app_name = row['app_name']
                existing_data[app_name] = {
                    'app_name': app_name,
                    'user_name': row.get('UserName', 'liz'),
                    'packets_sent': int(row.get('packets_sent', 0)),
                    'packets_recv': int(row.get('packets_recv', 0)),
                    'bytes_sent': int(row.get('bytes_sent', 0)),
                    'bytes_recv': int(row.get('bytes_recv', 0)),
                    'connections': int(row.get('connections', 0)),
                    'first_seen': row.get('first_seen', ''),
                    'last_seen': row.get('last_seen', '')
                }
    except Exception as e:
        print(f"警告: 读取已有 report.csv 失败: {e}", file=sys.stderr)
    
    return existing_data

def merge_with_existing_data(new_data, existing_data):
    """将新数据与已有数据合并"""
    from datetime import datetime
    
    for app_name, new_record in new_data.items():
        if app_name not in existing_data:
            # 新应用，直接添加
            existing_data[app_name] = new_record
        else:
            # 已存在的应用，累加统计数据
            existing_data[app_name]['packets_sent'] += new_record['packets_sent']
            existing_data[app_name]['packets_recv'] += new_record['packets_recv']
            existing_data[app_name]['bytes_sent'] += new_record['bytes_sent']
            existing_data[app_name]['bytes_recv'] += new_record['bytes_recv']
            existing_data[app_name]['connections'] += new_record['connections']
            
            # 更新时间范围
            try:
                existing_first = datetime.strptime(existing_data[app_name]['first_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                existing_last = datetime.strptime(existing_data[app_name]['last_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                new_first = datetime.strptime(new_record['first_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                new_last = datetime.strptime(new_record['last_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                
                if new_first < existing_first:
                    existing_data[app_name]['first_seen'] = new_record['first_seen']
                if new_last > existing_last:
                    existing_data[app_name]['last_seen'] = new_record['last_seen']
            except:
                # 如果时间解析失败，使用新数据的时间
                pass
    
    return existing_data

def main():
    # 配置路径
    script_dir = Path(__file__).parent
    base_dir = script_dir.parent
    features_dir = base_dir / "features"
    # 支持通过环境变量覆盖输出目录（用于按时间窗口多次运行）
    output_dir = Path(os.environ.get("SNIF_PROCESS_OUTPUT_DIR", str(script_dir / "output")))
    pred_file = output_dir / "predictions.txt"
    output_csv = output_dir / "report.csv"
    
    # 检查文件是否存在
    if not os.path.exists(pred_file):
        print(f"错误: 找不到预测结果文件 {pred_file}", file=sys.stderr)
        print("请先运行 test_model.py 并将输出重定向到 predictions.txt", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(features_dir):
        print(f"错误: 找不到features目录 {features_dir}", file=sys.stderr)
        sys.exit(1)
    
    # 加载预测结果
    print("加载预测结果...", file=sys.stderr)
    predictions = load_predictions(pred_file)
    print(f"加载了 {len(predictions)} 条预测结果", file=sys.stderr)
    
    # 收集classified目录下的分类结果
    classified_dir = output_dir / "classified"
    print("收集classified目录下的分类结果...", file=sys.stderr)
    classified_stats = aggregate_classified_stats(classified_dir)
    print(f"找到 {len(classified_stats)} 个分类类别", file=sys.stderr)
    
    # 收集所有流的数据（从features目录）
    print("收集流统计信息...", file=sys.stderr)
    flow_dirs = sorted([d for d in features_dir.iterdir() if d.is_dir()])
    
    results = []
    
    # 添加classified目录下的分类结果
    for category_name, stats in classified_stats.items():
        results.append({
            'flow_name': f'classified_{category_name}',
            'app_name': category_name,
            'user_name': 'liz',
            'packets_sent': stats['packets_sent'],
            'packets_recv': stats['packets_recv'],
            'bytes_sent': stats['bytes_sent'],
            'bytes_recv': stats['bytes_recv'],
            'connections': stats['connections'],
            'first_seen': format_timestamp(stats['first_seen']),
            'last_seen': format_timestamp(stats['last_seen'])
        })
    
    # 添加从features目录解析的流数据
    for flow_dir in flow_dirs:
        flow_name = flow_dir.name
        
        # 获取预测标签
        label = predictions.get(flow_name, "unknown")
        
        # 聚合统计信息
        stats = aggregate_flow_stats(flow_dir, features_dir)
        
        if stats is None:
            continue
        
        results.append({
            'flow_name': flow_name,
            'app_name': label,
            'user_name': 'liz',
            'packets_sent': stats['packets_sent'],
            'packets_recv': stats['packets_recv'],
            'bytes_sent': stats['bytes_sent'],
            'bytes_recv': stats['bytes_recv'],
            'connections': stats['connections'],
            'first_seen': format_timestamp(stats['first_seen']),
            'last_seen': format_timestamp(stats['last_seen'])
        })
    
    # 按应用名称合并记录
    print("按应用名称合并记录...", file=sys.stderr)
    merged_results = {}
    
    for result in results:
        app_name = result['app_name']
        
        if app_name not in merged_results:
            # 创建新记录
            merged_results[app_name] = {
                'app_name': app_name,
                'user_name': result['user_name'],
                'packets_sent': result['packets_sent'],
                'packets_recv': result['packets_recv'],
                'bytes_sent': result['bytes_sent'],
                'bytes_recv': result['bytes_recv'],
                'connections': result['connections'],
                'first_seen_ts': result['first_seen'],
                'last_seen_ts': result['last_seen']
            }
        else:
            # 合并统计信息
            merged_results[app_name]['packets_sent'] += result['packets_sent']
            merged_results[app_name]['packets_recv'] += result['packets_recv']
            merged_results[app_name]['bytes_sent'] += result['bytes_sent']
            merged_results[app_name]['bytes_recv'] += result['bytes_recv']
            merged_results[app_name]['connections'] += result['connections']
            
            # first_seen取最小值，last_seen取最大值
            # 需要从时间字符串转换回时间戳进行比较
            from datetime import datetime
            try:
                current_first = datetime.strptime(merged_results[app_name]['first_seen_ts'], '%Y-%m-%d %H:%M:%S').timestamp()
                current_last = datetime.strptime(merged_results[app_name]['last_seen_ts'], '%Y-%m-%d %H:%M:%S').timestamp()
                new_first = datetime.strptime(result['first_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                new_last = datetime.strptime(result['last_seen'], '%Y-%m-%d %H:%M:%S').timestamp()
                
                if new_first < current_first:
                    merged_results[app_name]['first_seen_ts'] = result['first_seen']
                if new_last > current_last:
                    merged_results[app_name]['last_seen_ts'] = result['last_seen']
            except:
                # 如果时间解析失败，保持原值
                pass
    
    # 转换为列表并按应用名称排序
    merged_list = list(merged_results.values())
    merged_list.sort(key=lambda x: x['app_name'])
    
    # 加载已有的 report.csv（如果存在）
    print("加载已有的 report.csv（增量模式）...", file=sys.stderr)
    existing_data = load_existing_report(output_csv)
    print(f"已有 {len(existing_data)} 个应用记录", file=sys.stderr)
    
    # 将新数据转换为字典格式
    new_data_dict = {}
    for result in merged_list:
        new_data_dict[result['app_name']] = {
            'app_name': result['app_name'],
            'user_name': result['user_name'],
            'packets_sent': result['packets_sent'],
            'packets_recv': result['packets_recv'],
            'bytes_sent': result['bytes_sent'],
            'bytes_recv': result['bytes_recv'],
            'connections': result['connections'],
            'first_seen': result['first_seen_ts'],
            'last_seen': result['last_seen_ts']
        }
    
    # 合并数据
    final_data = merge_with_existing_data(new_data_dict, existing_data)
    print(f"合并后共 {len(final_data)} 个应用", file=sys.stderr)
    
    # 转换为列表并按应用名称排序
    final_list = list(final_data.values())
    final_list.sort(key=lambda x: x['app_name'])
    
    # 写入CSV文件
    print(f"生成CSV报告: {output_csv}", file=sys.stderr)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'app_name', 'UserName', 'packets_sent', 'packets_recv',
            'bytes_sent', 'bytes_recv', 'connections', 'first_seen', 'last_seen'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in final_list:
            writer.writerow({
                'app_name': result['app_name'],
                'UserName': result['user_name'],
                'packets_sent': result['packets_sent'],
                'packets_recv': result['packets_recv'],
                'bytes_sent': result['bytes_sent'],
                'bytes_recv': result['bytes_recv'],
                'connections': result['connections'],
                'first_seen': result['first_seen'],
                'last_seen': result['last_seen']
            })
    
    print(f"完成！共生成 {len(final_list)} 条应用记录（增量合并）", file=sys.stderr)
    print(f"CSV文件: {output_csv}", file=sys.stderr)

if __name__ == "__main__":
    main()

