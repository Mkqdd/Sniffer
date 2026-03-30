#!/bin/bash

# 脚本功能：
# 增量处理多个 PCAP 文件，每个文件完整执行所有步骤
# 1. 运行split分析流并写入数据库
# 2. 解析unknown目录下的pcap文件
# 3. 运行应用分类模型
# 4. 生成CSV报告
# 5. 更新数据库（增量添加process_stats）
# 每个文件处理完成后等待5秒，然后处理下一个文件
# 使用方法: ./process.sh [输入pcap文件或目录]

# 移除 set -e，允许脚本在某些命令失败时继续执行
# set -e

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLIT_BIN="${SCRIPT_DIR}/split"
PCAP_PARSER_BIN="${SCRIPT_DIR}/../pcap_parser"
# 离线SSL黑名单扫描器：优先使用 sniffer/ 目录内的 sniffer_sslscan，其次使用项目根目录的 sniffer_sslscan
SSL_SCAN_BIN="${SCRIPT_DIR}/../sniffer_sslscan"
if [ ! -f "$SSL_SCAN_BIN" ] && [ -f "${SCRIPT_DIR}/../../sniffer_sslscan" ]; then
    SSL_SCAN_BIN="${SCRIPT_DIR}/../../sniffer_sslscan"
fi
INPUT_PATH="${1:-${SCRIPT_DIR}/test_pcaps}"
# 允许通过环境变量覆盖输出目录（用于“按时间窗口”多次运行，避免互相覆盖）
OUTPUT_DIR="${SNIF_PROCESS_OUTPUT_DIR:-${SCRIPT_DIR}/output}"
DATA_DIR="${SCRIPT_DIR}/domain-list-community/data"
ENTITY_MAP="${SCRIPT_DIR}/domain-list-community/entity_map.json"
INTERVAL_SECONDS=0.1  # 处理间隔时间（秒）
VENV_DIR="${SCRIPT_DIR}/venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

# 颜色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "=========================================="
echo " 网络流量分析工具"
echo "=========================================="
echo "输入路径: $INPUT_PATH"
echo "输出目录: $OUTPUT_DIR"
echo "处理间隔: ${INTERVAL_SECONDS}秒"
echo ""

# 检查依赖
echo "[检查] 检查依赖项..."
if [ ! -f "$SPLIT_BIN" ]; then
    echo -e "${RED}[错误]${NC} 找不到split: $SPLIT_BIN"
    exit 1
fi
if [ ! -f "$PCAP_PARSER_BIN" ]; then
    echo -e "${RED}[错误]${NC} 找不到pcap_parser: $PCAP_PARSER_BIN"
    exit 1
fi

# ssl black list scan tool is optional (for replay alerts)
if [ ! -f "$SSL_SCAN_BIN" ]; then
    echo -e "${YELLOW}[提示]${NC} 未找到离线SSL黑名单扫描器: $SSL_SCAN_BIN"
    echo -e "${YELLOW}[提示]${NC} 可在项目 sniffer 目录执行（生成到 sniffer/ 目录内）：go build -o ./sniffer_sslscan ./cmd/sslblacklist_scan"
    echo -e "${YELLOW}[提示]${NC} 或生成到项目根目录：go build -o ../sniffer_sslscan ./cmd/sslblacklist_scan"
else
    echo -e "${GREEN}[成功]${NC} 使用离线SSL黑名单扫描器: $SSL_SCAN_BIN"
fi
if [ ! -e "$INPUT_PATH" ]; then
    echo -e "${RED}[错误]${NC} 找不到输入路径: $INPUT_PATH"
    exit 1
fi

# 检查Python虚拟环境
if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${YELLOW}[警告]${NC} 找不到Python虚拟环境: $VENV_DIR"
    echo -e "${YELLOW}[警告]${NC} 将使用系统Python，可能会缺少依赖"
    echo -e "${YELLOW}[提示]${NC} 请运行部署脚本创建虚拟环境: ../deploy_linux.sh"
    VENV_PYTHON="python3"
else
    echo -e "${GREEN}[成功]${NC} 使用Python虚拟环境: $VENV_PYTHON"
fi

echo -e "${GREEN}[成功]${NC} 依赖项检查通过"
echo ""

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 预先检查并修复可能的权限问题
echo "[检查] 检查输出目录权限..."
permission_issues=false

# 检查并尝试修复 unknown 目录权限
if [ -d "${OUTPUT_DIR}/unknown" ] && [ ! -w "${OUTPUT_DIR}/unknown" ]; then
    echo -e "${YELLOW}[警告]${NC} unknown 目录没有写权限"
    permission_issues=true
fi

# 检查并尝试修复 classified 目录权限
if [ -d "${OUTPUT_DIR}/classified" ] && [ ! -w "${OUTPUT_DIR}/classified" ]; then
    echo -e "${YELLOW}[警告]${NC} classified 目录没有写权限"
    permission_issues=true
fi

# 如果发现权限问题，提供解决方案
if [ "$permission_issues" = true ]; then
    echo ""
    echo -e "${YELLOW}[提示]${NC} 发现权限问题，建议先修复权限："
    echo "  sudo chown -R \$USER:\$USER ${OUTPUT_DIR}"
    echo "  sudo chown -R \$USER:\$USER ${SCRIPT_DIR}/../features"
    echo ""
    read -p "是否尝试自动修复权限? 需要 sudo (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "修复权限..."
        sudo chown -R $USER:$USER "${OUTPUT_DIR}" 2>/dev/null || true
        sudo chown -R $USER:$USER "${SCRIPT_DIR}/../features" 2>/dev/null || true
        sudo chmod -R u+w "${OUTPUT_DIR}" 2>/dev/null || true
        sudo chmod -R u+w "${SCRIPT_DIR}/../features" 2>/dev/null || true
        echo -e "${GREEN}[完成]${NC} 权限已修复"
        echo ""
    fi
fi

# 收集所有 PCAP 文件
echo "[扫描] 收集PCAP文件..."
PCAP_FILES=()
if [ -d "$INPUT_PATH" ]; then
    while IFS= read -r -d '' file; do
        PCAP_FILES+=("$file")
    done < <(find "$INPUT_PATH" -type f \( -name "*.pcap" -o -name "*.cap" \) -print0 | sort -z)
else
    PCAP_FILES=("$INPUT_PATH")
fi

TOTAL_FILES=${#PCAP_FILES[@]}
echo "找到 $TOTAL_FILES 个PCAP文件"
echo ""

if [ $TOTAL_FILES -eq 0 ]; then
    echo -e "${RED}[错误]${NC} 没有找到PCAP文件"
    exit 1
fi

# 显示将要处理的文件列表
echo "文件列表:"
for i in "${!PCAP_FILES[@]}"; do
    echo "  $((i+1)). $(basename "${PCAP_FILES[$i]}")"
done
echo ""

# 初始化累计统计变量
CUMULATIVE_TOTAL_FLOWS=0
CUMULATIVE_CLASSIFIED_FLOWS=0

# 处理每个 PCAP 文件的函数
process_single_pcap() {
    local pcap_file="$1"
    local file_num="$2"
    local total_files="$3"
    local filename=$(basename "$pcap_file")
    
    echo ""
    echo "=========================================="
    echo -e "${BLUE}[${file_num}/${total_files}] 处理文件: $filename${NC}"
    echo "=========================================="
    echo ""
    
    # 清空 unknown 和 classified 目录（每个 pcap 独立处理）
    echo "[清理] 清空 unknown、classified 和 features 目录..."
    
    # 尝试修改权限并删除，如果失败则提示使用 sudo
    local cleanup_failed=false
    
    # 清理 unknown 目录
    if [ -d "${OUTPUT_DIR}/unknown" ]; then
        chmod -R u+w "${OUTPUT_DIR}/unknown" 2>/dev/null || true
        if ! rm -rf "${OUTPUT_DIR}/unknown" 2>/dev/null; then
            echo -e "${YELLOW}[警告]${NC} 无法删除 unknown 目录 (权限问题)"
            cleanup_failed=true
        fi
    fi
    
    # 清理 classified 目录
    if [ -d "${OUTPUT_DIR}/classified" ]; then
        chmod -R u+w "${OUTPUT_DIR}/classified" 2>/dev/null || true
        if ! rm -rf "${OUTPUT_DIR}/classified" 2>/dev/null; then
            echo -e "${YELLOW}[警告]${NC} 无法删除 classified 目录 (权限问题)"
            cleanup_failed=true
        fi
    fi
    
    # 清理 features 目录
    if [ -d "${SCRIPT_DIR}/../features" ]; then
        chmod -R u+w "${SCRIPT_DIR}/../features" 2>/dev/null || true
        if ! rm -rf "${SCRIPT_DIR}/../features"/* 2>/dev/null; then
            echo -e "${YELLOW}[警告]${NC} 无法删除 features 目录内容 (权限问题)"
            cleanup_failed=true
        fi
    fi
    
    # 如果清理失败，提示用户解决方案
    if [ "$cleanup_failed" = true ]; then
        echo ""
        echo -e "${RED}[错误]${NC} 部分文件/目录清理失败，可能原因："
        echo "  1. 文件由 root 或其他用户创建"
        echo "  2. 文件权限被保护"
        echo ""
        echo "解决方案："
        echo "  选项1: 使用 sudo 运行此脚本"
        echo "    sudo ./process.sh"
        echo ""
        echo "  选项2: 手动清理这些目录"
        echo "    sudo rm -rf ${OUTPUT_DIR}/unknown ${OUTPUT_DIR}/classified"
        echo "    sudo rm -rf ${SCRIPT_DIR}/../features/*"
        echo ""
        echo "  选项3: 修改文件所有权"
        echo "    sudo chown -R \$USER:\$USER ${OUTPUT_DIR}"
        echo "    sudo chown -R \$USER:\$USER ${SCRIPT_DIR}/../features"
        echo ""
    # 这里是交互式确认逻辑：
    # 1) 当脚本在终端直接手动运行时，允许用户选择是否继续
    # 2) 当脚本在后台/非交互模式被其他进程调用时（没有 stdin），不应该卡住或因空输入取消
    if [ "${SNIF_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
        echo "[非交互模式] 继续处理（即使可能失败）"
        REPLY="y"
    else
        read -p "是否继续处理 (可能会失败)? (y/N): " -n 1 -r
        echo
    fi
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "已取消处理"
        exit 1
    fi
    fi
    
    # 重新创建目录
    mkdir -p "${OUTPUT_DIR}/unknown"
    mkdir -p "${OUTPUT_DIR}/classified"
    mkdir -p "${SCRIPT_DIR}/../features"
    
    echo -e "${GREEN}[完成]${NC} 目录清理完成，准备处理新文件"
    echo ""
    
    # 步骤1：运行split分析流
    echo "--- 步骤1: 运行split分析流 ---"
    
    # 运行split并捕获输出
    local split_output=$(mktemp)
    "$SPLIT_BIN" \
        --input "$pcap_file" \
        --output "$OUTPUT_DIR" \
        --data-dir "$DATA_DIR" \
        --entity-map "$ENTITY_MAP" \
        > "$split_output" 2>&1
    
    local split_exit_code=$?
    
    # 保存完整日志
    cp "$split_output" "${OUTPUT_DIR}/split_${file_num}.log"
    
    if [ $split_exit_code -ne 0 ]; then
        echo -e "${RED}[失败]${NC} split执行失败"
        cat "${OUTPUT_DIR}/split_${file_num}.log"
        rm -f "$split_output"
        return 1
    fi
    
    echo -e "${GREEN}[成功]${NC} split执行完成"
    
    # 解析split输出的统计信息（从stdout第一行提取）
    local stats_line=$(grep "^STATS:" "$split_output" | head -n 1)
    accuracy_value=""  # 全局变量，不使用local
    
    if [ -n "$stats_line" ]; then
        # 格式: STATS:total_flows,classified_flows,unknown_flows,accuracy
        accuracy_value=$(echo "$stats_line" | cut -d':' -f2 | cut -d',' -f4)
        local total_flows=$(echo "$stats_line" | cut -d':' -f2 | cut -d',' -f1)
        local classified_flows=$(echo "$stats_line" | cut -d':' -f2 | cut -d',' -f2)
        local unknown_flows=$(echo "$stats_line" | cut -d':' -f2 | cut -d',' -f3)
        
        # 累加全局统计
        CUMULATIVE_TOTAL_FLOWS=$((CUMULATIVE_TOTAL_FLOWS + total_flows))
        CUMULATIVE_CLASSIFIED_FLOWS=$((CUMULATIVE_CLASSIFIED_FLOWS + classified_flows))
        
        echo "  本文件分类统计: 总流数=$total_flows, 成功分类=$classified_flows, 未分类=$unknown_flows"
        echo "  本文件准确率: ${accuracy_value}%"
        echo "  累计统计: 总流数=$CUMULATIVE_TOTAL_FLOWS, 成功分类=$CUMULATIVE_CLASSIFIED_FLOWS"
    fi
    
    rm -f "$split_output"
    
    # 显示数据库统计
    local db_file="${OUTPUT_DIR}/sniffer.db"
    if [ -f "$db_file" ]; then
        local dns_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM dns_sessions;" 2>/dev/null || echo "0")
        local flow_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM session_flows;" 2>/dev/null || echo "0")
        echo "  数据库状态: DNS会话=$dns_count, 会话流=$flow_count"
    fi
    echo ""

    # SSL 黑名单告警（JA3/证书SHA1）：离线扫描 PCAP 并写入 alert_logs，供前端 replay 模式展示
    if [ -f "$SSL_SCAN_BIN" ] && [ -f "$db_file" ]; then
        local blacklist_dir="${SCRIPT_DIR}/../SSLBlackList"
        if [ -n "$SNIF_SSL_BLACKLIST_DIR" ]; then
            blacklist_dir="$SNIF_SSL_BLACKLIST_DIR"
        fi
        if [ -d "$blacklist_dir" ]; then
            echo "--- SSL黑名单扫描: 提取JA3/证书SHA1 并写告警 ---"
            "$SSL_SCAN_BIN" -pcap "$pcap_file" -db "$db_file" -blacklist-dir "$blacklist_dir" 2>&1 | tail -n 5 || true
            # 显示告警数量
            local alert_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM alert_logs WHERE rule_type='ssl_blacklist';" 2>/dev/null || echo "0")
            echo "  SSL黑名单告警数: $alert_count"
            echo ""
        fi
    fi
    
    # 步骤2：解析unknown目录下的pcap文件
    echo "--- 步骤2: 解析unknown目录 ---"
    
    local unknown_dir="${OUTPUT_DIR}/unknown"
    local features_dir="${SCRIPT_DIR}/../features"
    
    if [ ! -d "$unknown_dir" ]; then
        echo -e "${YELLOW}[跳过]${NC} unknown目录不存在"
    else
        local pcap_count=$(find "$unknown_dir" -name "*.pcap" -type f 2>/dev/null | wc -l)
        
        if [ "$pcap_count" -eq 0 ]; then
            echo -e "${YELLOW}[跳过]${NC} unknown目录下没有pcap文件"
        else
            echo "找到 $pcap_count 个pcap文件需要解析"
            
            local success_count=0
            local fail_count=0
            
            mkdir -p "$features_dir"
            
            for unknown_pcap in "$unknown_dir"/*.pcap; do
                if [ ! -f "$unknown_pcap" ]; then
                    continue
                fi
                
                local unknown_filename=$(basename "$unknown_pcap")
                local file_basename="${unknown_filename%.pcap}"
                local file_output_dir="${features_dir}/${file_basename}"
                
                mkdir -p "$file_output_dir"
                
                "$PCAP_PARSER_BIN" \
                    -i "$unknown_pcap" \
                    -o "$file_output_dir" \
                    -j \
                    > "$file_output_dir/parser.log" 2>&1
                
                if [ $? -eq 0 ]; then
                    success_count=$((success_count + 1))
                else
                    fail_count=$((fail_count + 1))
                fi
            done
            
            echo -e "${GREEN}[成功]${NC} 解析完成: 成功=$success_count, 失败=$fail_count"
        fi
    fi
    echo ""
    
    # 步骤3：运行应用分类模型
    echo "--- 步骤3: 运行应用分类模型 ---"
    
    local test_model_script="${SCRIPT_DIR}/test_model.py"
    local predictions_file="${OUTPUT_DIR}/predictions.txt"
    
    if [ ! -f "$test_model_script" ]; then
        echo -e "${YELLOW}[跳过]${NC} 找不到test_model.py"
    else
        "$VENV_PYTHON" "$test_model_script" 2>&1 | grep -E "^[0-9a-zA-Z].*," > "$predictions_file" || true
        
        if [ ! -s "$predictions_file" ]; then
            echo -e "${YELLOW}[警告]${NC} test_model.py未生成预测结果"
        else
            local prediction_count=$(grep -c "," "$predictions_file" 2>/dev/null || echo "0")
            echo -e "${GREEN}[成功]${NC} 应用分类完成: $prediction_count 条流"
        fi
    fi
    echo ""
    
    # 步骤4：生成CSV报告
    echo "--- 步骤4: 生成CSV报告 ---"
    
    local generate_report_bin="${SCRIPT_DIR}/generate_report"
    local generate_report_script="${SCRIPT_DIR}/generate_report.py"
    local report_csv="${OUTPUT_DIR}/report.csv"
    
    if [ -f "$generate_report_bin" ]; then
        "$generate_report_bin" > /dev/null 2>&1
    elif [ -f "$generate_report_script" ]; then
        "$VENV_PYTHON" "$generate_report_script" > /dev/null 2>&1
    else
        echo -e "${YELLOW}[跳过]${NC} 找不到generate_report"
    fi
    
    if [ -f "$report_csv" ]; then
        local report_count=$(tail -n +2 "$report_csv" 2>/dev/null | wc -l || echo "0")
        echo -e "${GREEN}[成功]${NC} CSV报告已生成: $report_count 条记录"
    else
        echo -e "${YELLOW}[跳过]${NC} CSV报告未生成"
    fi
    echo ""
    
    # 步骤5：更新数据库（增量添加 process_stats）
    echo "--- 步骤5: 更新数据库 (process_stats) ---"
    
    local generate_db_script="${SCRIPT_DIR}/generate_db.py"
    
    if [ ! -f "$generate_db_script" ]; then
        echo -e "${YELLOW}[跳过]${NC} 找不到generate_db.py"
    elif [ ! -f "$report_csv" ]; then
        echo -e "${YELLOW}[跳过]${NC} 找不到report.csv"
    else
        "$VENV_PYTHON" "$generate_db_script" 2>&1 | grep -E "(成功|导入|错误|警告)" || true
        
        if [ -f "$db_file" ]; then
            local process_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM process_stats;" 2>/dev/null || echo "0")
            echo -e "${GREEN}[成功]${NC} process_stats表已更新: $process_count 条记录"
        fi
    fi
    
    # 更新累计分类统计到数据库
    if [ -f "$db_file" ] && [ $CUMULATIVE_TOTAL_FLOWS -gt 0 ]; then
        # 创建 classification_stats 表（如果不存在）
        sqlite3 "$db_file" "CREATE TABLE IF NOT EXISTS classification_stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_flows INTEGER NOT NULL DEFAULT 0,
            classified_flows INTEGER NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );" 2>/dev/null
        
        # 更新累计统计
        sqlite3 "$db_file" "INSERT OR REPLACE INTO classification_stats (id, total_flows, classified_flows, updated_at) 
                            VALUES (1, $CUMULATIVE_TOTAL_FLOWS, $CUMULATIVE_CLASSIFIED_FLOWS, CURRENT_TIMESTAMP);" 2>/dev/null
        
        # 计算累计准确率
        local cumulative_accuracy=$(echo "scale=2; $CUMULATIVE_CLASSIFIED_FLOWS * 100 / $CUMULATIVE_TOTAL_FLOWS" | bc)
        echo "  累计分类准确率: ${cumulative_accuracy}% (已分类=$CUMULATIVE_CLASSIFIED_FLOWS / 总计=$CUMULATIVE_TOTAL_FLOWS)"
    fi
    
    # 显示本次处理后的完整统计
    echo ""
    echo "当前数据库统计:"
    if [ -f "$db_file" ]; then
        local dns_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM dns_sessions;" 2>/dev/null || echo "0")
        local flow_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM session_flows;" 2>/dev/null || echo "0")
        local process_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM process_stats;" 2>/dev/null || echo "0")
        echo "  - DNS会话: $dns_count"
        echo "  - 会话流: $flow_count"
        echo "  - 进程统计: $process_count"
    fi
    
    # 输出进度信息（供后端捕获） - 必须输出，确保前端收到通知
    echo "PROGRESS:FILE_COMPLETED:$filename"
    echo ""
    
    return 0
}

# 增量处理每个PCAP文件
PROCESSED_COUNT=0
FAILED_COUNT=0
LAST_ACCURACY=""
accuracy_value=""  # 全局变量

for i in "${!PCAP_FILES[@]}"; do
    pcap_file="${PCAP_FILES[$i]}"
    file_num=$((i+1))
    
    process_single_pcap "$pcap_file" "$file_num" "$TOTAL_FILES"
    
    if [ $? -eq 0 ]; then
        PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
        # 保存最后一次的准确率
        if [ -n "$accuracy_value" ]; then
            LAST_ACCURACY="$accuracy_value"
        fi
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
    
    # 如果不是最后一个文件，等待间隔时间
    # if [ $file_num -lt $TOTAL_FILES ]; then
    #     echo ""
    #     echo -e "${YELLOW}等待 ${INTERVAL_SECONDS} 秒后处理下一个文件...${NC}"
    #     # sleep $INTERVAL_SECONDS
    # fi
done

# 最终总结
echo ""
echo "=========================================="
echo -e "${GREEN}[完成] 所有处理完成！${NC}"
echo "=========================================="
echo "处理统计:"
echo "  - 总文件数: $TOTAL_FILES"
echo "  - 成功: $PROCESSED_COUNT"
if [ $FAILED_COUNT -gt 0 ]; then
    echo "  - 失败: $FAILED_COUNT"
fi
echo ""

# 显示最终数据库统计
DB_FILE="${OUTPUT_DIR}/sniffer.db"
if [ -f "$DB_FILE" ]; then
    echo "最终数据库统计 ($DB_FILE):"
    dns_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM dns_sessions;" 2>/dev/null || echo "0")
    flow_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM session_flows;" 2>/dev/null || echo "0")
    process_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM process_stats;" 2>/dev/null || echo "0")
    echo "  - DNS会话: $dns_count"
    echo "  - 会话流: $flow_count"
    echo "  - 进程统计: $process_count"
    echo ""
    db_size=$(ls -lh "$DB_FILE" | awk '{print $5}')
    echo "  数据库大小: $db_size"
fi

echo ""
echo "输出目录:"
echo "  - 输出根目录: $OUTPUT_DIR"
echo "  - 分类结果: $OUTPUT_DIR/classified/"
echo "  - 未分类流: $OUTPUT_DIR/unknown/"
echo "  - 解析结果: ${SCRIPT_DIR}/../features/"
echo "  - 数据库文件: $DB_FILE"
echo ""
