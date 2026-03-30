#!/usr/bin/env python3
"""
测试模型脚本
从features目录下的conn.log文件中提取特征，使用训练好的模型进行预测
对于每个流的多条conn.log记录，使用少数服从多数的原则确定最终预测结果
输出格式: flow_name,label
"""

import json
import os
import sys
import glob
from collections import Counter
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

def load_label_mapping(label_file):
    """加载标签映射"""
    with open(label_file, 'r', encoding='utf-8') as f:
        label2idx = eval(f.read())
    idx2label = {v: k for k, v in label2idx.items()}
    return label2idx, idx2label

def extract_features_from_conn_log_line(data):
    """
    从单条conn.log记录中提取特征
    返回特征字典
    """
    feature_dict = {}
    
    # 基本特征
    feature_dict['bytes_out'] = data.get('up_bytes', 0)
    feature_dict['bytes_in'] = data.get('down_bytes', 0)
    feature_dict['pkts_out'] = data.get('up_pkts', 0)
    feature_dict['pkts_in'] = data.get('down_pkts', 0)
    feature_dict['dur'] = data.get('duration', 0.0)
    
    # skew和kurtosis - 训练数据中是从所有数据包大小的绝对值计算的
    # 由于conn.log中没有原始数据包大小列表，我们使用加权平均来估算
    up_skew = data.get('up_size_skewness', 0.0)
    down_skew = data.get('down_size_skewness', 0.0)
    up_kurtosis = data.get('up_size_kurtosis', 0.0)
    down_kurtosis = data.get('down_size_kurtosis', 0.0)
    up_pkts = data.get('up_pkts', 0)
    down_pkts = data.get('down_pkts', 0)
    total_pkts = up_pkts + down_pkts
    
    if total_pkts > 0:
        # 使用数据包数量加权平均
        feature_dict['skew'] = (up_skew * up_pkts + down_skew * down_pkts) / total_pkts
        feature_dict['kurtosis'] = (up_kurtosis * up_pkts + down_kurtosis * down_pkts) / total_pkts
    else:
        # 如果没有数据包，使用up方向的统计值
        feature_dict['skew'] = up_skew
        feature_dict['kurtosis'] = up_kurtosis
    
    # 前向（up）数据包大小特征
    feature_dict['fw_pkt_l_max'] = data.get('up_max_size', 0)
    feature_dict['fw_pkt_l_min'] = data.get('up_min_size', 0)
    feature_dict['fw_pkt_l_avg'] = data.get('up_avg_size', 0.0)
    feature_dict['fw_pkt_l_median'] = data.get('up_median_size', 0.0)
    
    # 计算fw_pkt_l_std - 训练数据中使用np.std()计算真实标准差
    # 由于conn.log中没有原始数据包大小列表，我们使用多种方法估算
    up_q1 = data.get('up_first_quartile', 0.0)
    up_q3 = data.get('up_third_quartile', 0.0)
    up_min = data.get('up_min_size', 0)
    up_max = data.get('up_max_size', 0)
    up_avg = data.get('up_avg_size', 0.0)
    
    if up_q3 > up_q1:
        # 方法1: 使用四分位数范围估算 (Q3 - Q1) / 1.35
        feature_dict['fw_pkt_l_std'] = (up_q3 - up_q1) / 1.35
    elif up_max > up_min:
        # 方法2: 如果Q3==Q1，使用范围估算 (max - min) / 4
        feature_dict['fw_pkt_l_std'] = (up_max - up_min) / 4.0
    else:
        # 方法3: 如果所有值都相同，std为0
        feature_dict['fw_pkt_l_std'] = 0.0
    
    # 后向（down）数据包大小特征
    feature_dict['bw_pkt_l_max'] = data.get('down_max_size', 0)
    feature_dict['bw_pkt_l_min'] = data.get('down_min_size', 0)
    feature_dict['bw_pkt_l_avg'] = data.get('down_avg_size', 0.0)
    feature_dict['bw_pkt_l_median'] = data.get('down_median_size', 0.0)
    
    # 计算bw_pkt_l_std
    down_q1 = data.get('down_first_quartile', 0.0)
    down_q3 = data.get('down_third_quartile', 0.0)
    down_min = data.get('down_min_size', 0)
    down_max = data.get('down_max_size', 0)
    down_avg = data.get('down_avg_size', 0.0)
    
    if down_q3 > down_q1:
        # 方法1: 使用四分位数范围估算
        feature_dict['bw_pkt_l_std'] = (down_q3 - down_q1) / 1.35
    elif down_max > down_min:
        # 方法2: 如果Q3==Q1，使用范围估算
        feature_dict['bw_pkt_l_std'] = (down_max - down_min) / 4.0
    else:
        # 方法3: 如果所有值都相同，std为0
        feature_dict['bw_pkt_l_std'] = 0.0
    
    # 前向（up）IAT特征
    feature_dict['fw_iat_max'] = data.get('up_max_iat', 0.0)
    feature_dict['fw_iat_min'] = data.get('up_min_iat', 0.0)
    feature_dict['fw_iat_avg'] = data.get('up_avg_iat', 0.0)
    feature_dict['fw_iat_median'] = data.get('up_median_iat', 0.0)
    
    # 计算fw_iat_std
    up_iat_q1 = data.get('up_first_quartile_iat', 0.0)
    up_iat_q3 = data.get('up_third_quartile_iat', 0.0)
    up_iat_min = data.get('up_min_iat', 0.0)
    up_iat_max = data.get('up_max_iat', 0.0)
    
    if up_iat_q3 > up_iat_q1:
        feature_dict['fw_iat_std'] = (up_iat_q3 - up_iat_q1) / 1.35
    elif up_iat_max > up_iat_min:
        feature_dict['fw_iat_std'] = (up_iat_max - up_iat_min) / 4.0
    else:
        feature_dict['fw_iat_std'] = 0.0
    
    # 后向（down）IAT特征
    feature_dict['bw_iat_max'] = data.get('down_max_iat', 0.0)
    feature_dict['bw_iat_min'] = data.get('down_min_iat', 0.0)
    feature_dict['bw_iat_avg'] = data.get('down_avg_iat', 0.0)
    feature_dict['bw_iat_median'] = data.get('down_median_iat', 0.0)
    
    # 计算bw_iat_std
    down_iat_q1 = data.get('down_first_quartile_iat', 0.0)
    down_iat_q3 = data.get('down_third_quartile_iat', 0.0)
    down_iat_min = data.get('down_min_iat', 0.0)
    down_iat_max = data.get('down_max_iat', 0.0)
    
    if down_iat_q3 > down_iat_q1:
        feature_dict['bw_iat_std'] = (down_iat_q3 - down_iat_q1) / 1.35
    elif down_iat_max > down_iat_min:
        feature_dict['bw_iat_std'] = (down_iat_max - down_iat_min) / 4.0
    else:
        feature_dict['bw_iat_std'] = 0.0
    
    return feature_dict

def predict_flow(features_list, model, feature_names, idx2label):
    """
    对一条流的多条conn.log记录进行预测
    使用少数服从多数的原则
    """
    if not features_list:
        return None
    
    # 转换为DataFrame
    df = pd.DataFrame(features_list)
    
    # 确保所有特征都存在
    for feat in feature_names:
        if feat not in df.columns:
            df[feat] = 0.0
    
    # 提取特征
    X = df[feature_names]
    
    # 预测
    predictions = model.predict(X)
    
    # 统计预测结果
    pred_counts = Counter(predictions)
    
    # 少数服从多数
    most_common_pred = pred_counts.most_common(1)[0][0]
    
    # 转换为标签名
    label = idx2label.get(most_common_pred, f"unknown(预测ID:{most_common_pred})")
    
    return label, len(predictions), pred_counts

def main():
    # 配置路径
    base_dir = Path(__file__).parent.parent
    features_dir = base_dir / "features"
    model_path = base_dir / "model" / "RF_app.pkl"
    label_file = base_dir / "model" / "label.json"
    
    # 检查文件是否存在
    if not os.path.exists(model_path):
        print(f"错误: 找不到模型文件 {model_path}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(label_file):
        print(f"错误: 找不到标签文件 {label_file}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(features_dir):
        print(f"错误: 找不到features目录 {features_dir}", file=sys.stderr)
        sys.exit(1)
    
    # 加载模型和标签映射
    print("加载模型和标签映射...", file=sys.stderr)
    model = joblib.load(model_path)
    label2idx, idx2label = load_label_mapping(label_file)
    
    # 获取特征名称（按训练时的顺序）
    feature_names = [
        'bytes_out', 'pkts_out', 'bytes_in', 'pkts_in', 'dur', 'skew', 'kurtosis',
        'fw_pkt_l_max', 'fw_pkt_l_min', 'fw_pkt_l_avg', 'fw_pkt_l_std',
        'bw_pkt_l_max', 'bw_pkt_l_min', 'bw_pkt_l_avg', 'bw_pkt_l_std',
        'fw_iat_max', 'fw_iat_min', 'fw_iat_avg', 'fw_iat_std',
        'bw_iat_max', 'bw_iat_min', 'bw_iat_avg', 'bw_iat_std',
        'fw_pkt_l_median', 'bw_pkt_l_median', 'fw_iat_median', 'bw_iat_median'
    ]
    
    # 遍历features目录下的所有流目录
    print("处理流特征...", file=sys.stderr)
    flow_dirs = sorted([d for d in features_dir.iterdir() if d.is_dir()])
    
    results = []
    
    for flow_dir in flow_dirs:
        # 查找conn.log文件（可能在子目录中）
        conn_log_paths = list(flow_dir.rglob("conn.log"))
        
        if not conn_log_paths:
            continue
        
        # 合并所有conn.log文件的内容
        all_features = []
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
                    
                    # 提取特征
                    feature_dict = extract_features_from_conn_log_line(data)
                    all_features.append(feature_dict)
        
        if not all_features:
            continue
        
        # 预测
        flow_name = flow_dir.name
        label, num_records, pred_counts = predict_flow(all_features, model, feature_names, idx2label)
        
        if label is not None:
            results.append({
                'flow': flow_name,
                'label': label,
                'num_records': num_records,
                'prediction_distribution': dict(pred_counts)
            })
    
    # 输出结果（按流名称排序）
    results.sort(key=lambda x: x['flow'])
    
    for result in results:
        flow_name = result['flow']
        label = result['label']
        
        # 输出格式: flow_name,label
        print(f"{flow_name},{label}")
    
    print(f"\n处理完成，共处理 {len(results)} 条流", file=sys.stderr)

if __name__ == "__main__":
    main()

