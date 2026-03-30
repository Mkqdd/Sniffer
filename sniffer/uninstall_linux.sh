#!/bin/bash

#############################################################
# FastMonitor Linux 完全卸载脚本
# 功能: 完全清除 deploy_linux.sh 安装的所有内容
#############################################################

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

# 确认函数
confirm() {
    local prompt="$1"
    local default="${2:-N}"
    
    if [ "$default" = "Y" ]; then
        read -p "$prompt (Y/n): " -n 1 -r
    else
        read -p "$prompt (y/N): " -n 1 -r
    fi
    echo
    
    if [ -z "$REPLY" ]; then
        [ "$default" = "Y" ]
    else
        [[ $REPLY =~ ^[Yy]$ ]]
    fi
}

# 统计变量
REMOVED_COUNT=0
FAILED_COUNT=0

# 停止运行中的进程
stop_running_processes() {
    log_step "停止运行中的进程"
    
    local stopped=0
    
    # 查找并停止 wails dev 进程
    if pgrep -f "wails dev" > /dev/null 2>&1; then
        log_info "停止 wails dev 进程..."
        pkill -f "wails dev" 2>/dev/null && stopped=$((stopped + 1))
        sleep 2
    fi
    
    # 查找并停止 FastMonitor 相关进程
    if pgrep -f "sniffer" > /dev/null 2>&1 || pgrep -f "FastMonitor" > /dev/null 2>&1; then
        log_info "停止 FastMonitor 进程..."
        pkill -f "sniffer" 2>/dev/null && stopped=$((stopped + 1))
        pkill -f "FastMonitor" 2>/dev/null && stopped=$((stopped + 1))
        sleep 1
    fi
    
    if [ $stopped -gt 0 ]; then
        log_info "[OK] 已停止 $stopped 个进程"
    else
        log_info "未发现运行中的进程"
    fi
}

# 删除编译产物
remove_binaries() {
    log_step "删除编译产物"
    
    local items=(
        "pcap_parser"
        "domain/split"
        "domain/generate_report"
        "lzprobe/pcap_parser"
        "lzprobe/build"
    )
    
    for item in "${items[@]}"; do
        if [ -e "$item" ]; then
            log_info "删除 $item..."
            rm -rf "$item" && REMOVED_COUNT=$((REMOVED_COUNT + 1))
        fi
    done
    
    # 恢复备份的 Makefile
    if [ -f "lzprobe/Makefile.bak" ]; then
        log_info "恢复 lzprobe/Makefile 备份..."
        mv lzprobe/Makefile.bak lzprobe/Makefile && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    log_info "[OK] 编译产物清理完成"
}

# 删除 PcapPlusPlus
remove_pcapplusplus() {
    log_step "删除 PcapPlusPlus"
    
    # 查找所有 PcapPlusPlus 相关文件
    local found=0
    
    # 删除目录（支持新旧命名）
    for dir in pcapplusplus* pcap_plusplus*; do
        if [ -d "$dir" ]; then
            log_info "删除目录: $dir"
            rm -rf "$dir" && REMOVED_COUNT=$((REMOVED_COUNT + 1))
            found=1
        fi
    done
    
    # 删除压缩包
    for file in pcapplusplus*.tar.gz; do
        if [ -f "$file" ]; then
            log_info "删除压缩包: $file"
            rm -f "$file" && REMOVED_COUNT=$((REMOVED_COUNT + 1))
            found=1
        fi
    done
    
    if [ $found -eq 0 ]; then
        log_info "未找到 PcapPlusPlus 文件"
    else
        log_info "[OK] PcapPlusPlus 清理完成"
    fi
}

# 删除前端构建产物
remove_frontend() {
    log_step "删除前端构建产物"
    
    if [ ! -d "frontend" ]; then
        log_info "frontend 目录不存在"
        return
    fi
    
    cd frontend
    
    # 删除 dist 目录
    if [ -d "dist" ]; then
        log_info "删除 dist 目录..."
        chmod -R u+w dist 2>/dev/null || true
        rm -rf dist 2>/dev/null || sudo rm -rf dist
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除 node_modules
    if [ -d "node_modules" ]; then
        local size=$(du -sh node_modules 2>/dev/null | cut -f1)
        log_info "发现 node_modules ($size)"
        chmod -R u+w node_modules 2>/dev/null || true
        log_info "删除 node_modules (可能需要一些时间)..."
        rm -rf node_modules 2>/dev/null || sudo rm -rf node_modules
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除 package-lock.json
    if [ -f "package-lock.json" ]; then
        rm -f package-lock.json && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除 package.json.md5
    if [ -f "package.json.md5" ]; then
        rm -f package.json.md5 && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    cd ..
    log_info "[OK] 前端构建产物清理完成"
}

# 删除 Go 构建产物
remove_go_artifacts() {
    log_step "删除 Go 构建产物"
    
    # 清理 Go 缓存
    if command -v go >/dev/null 2>&1; then
        log_info "清理 Go 构建缓存..."
        go clean -cache -modcache -testcache 2>/dev/null || true
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除编译产物
    local items=(
        "sniffer"
        "FastMonitor"
        "build/bin"
    )
    
    for item in "${items[@]}"; do
        if [ -e "$item" ]; then
            log_info "删除 $item..."
            rm -rf "$item" && REMOVED_COUNT=$((REMOVED_COUNT + 1))
        fi
    done
    
    log_info "[OK] Go 构建产物清理完成"
}

# 删除 Python 虚拟环境
remove_python_venv() {
    log_step "删除 Python 虚拟环境"
    
    if [ -d "domain/venv" ]; then
        log_info "删除 domain/venv..."
        rm -rf domain/venv && REMOVED_COUNT=$((REMOVED_COUNT + 1))
        log_info "[OK] Python 虚拟环境已删除"
    else
        log_info "未找到 Python 虚拟环境"
    fi
}

# 删除生成的脚本
remove_generated_scripts() {
    log_step "删除生成的脚本"
    
    local scripts=(
        "start.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [ -f "$script" ]; then
            log_info "删除 $script..."
            rm -f "$script" && REMOVED_COUNT=$((REMOVED_COUNT + 1))
        fi
    done
    
    log_info "[OK] 生成的脚本清理完成"
}

# 删除配置文件
remove_config_files() {
    log_step "删除配置文件"
    
    log_warn "警告: 将删除所有配置文件！"
    
    if [ -f "config.yaml" ]; then
        log_info "删除 config.yaml..."
        rm -f config.yaml && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    log_info "[OK] 配置文件清理完成"
}

# 删除数据文件
remove_data_files() {
    log_step "删除数据文件"
    
    log_warn "警告: 将删除所有数据，包括数据库和 PCAP 文件！"
    echo
    
    if [ -d "data" ]; then
        local size=$(du -sh data 2>/dev/null | cut -f1)
        echo "data 目录大小: $size"
        echo
        
        log_info "删除 data 目录..."
        chmod -R u+w data 2>/dev/null || true
        rm -rf data 2>/dev/null || sudo rm -rf data
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    if [ -d "logs" ]; then
        log_info "删除 logs 目录..."
        rm -rf logs 2>/dev/null || sudo rm -rf logs
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除 domain 输出目录
    if [ -d "domain/output" ]; then
        log_info "删除 domain/output..."
        chmod -R u+w domain/output 2>/dev/null || true
        rm -rf domain/output 2>/dev/null || sudo rm -rf domain/output
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    # 删除 features 目录
    if [ -d "features" ]; then
        log_info "删除 features 目录..."
        chmod -R u+w features 2>/dev/null || true
        rm -rf features 2>/dev/null || sudo rm -rf features
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    fi
    
    log_info "[OK] 数据文件清理完成"
}

# 清理临时文件和缓存
clean_temp_files() {
    log_step "清理临时文件"
    
    # 删除各种临时文件
    find . -name ".DS_Store" -type f -delete 2>/dev/null && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    find . -name "*.log" -path "*/domain/*" -type f -delete 2>/dev/null && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null && REMOVED_COUNT=$((REMOVED_COUNT + 1))
    find . -name "*.pyc" -type f -delete 2>/dev/null
    find . -name ".cache" -type d -exec rm -rf {} + 2>/dev/null
    
    # 清理 wails 临时文件
    if [ -d "$HOME/.wails" ]; then
        log_info "清理 Wails 缓存..."
        rm -rf "$HOME/.wails/cache" 2>/dev/null
    fi
    
    log_info "[OK] 临时文件清理完成"
}

# 可选：卸载系统依赖
uninstall_system_dependencies() {
    log_step "卸载系统依赖（可选）"
    
    echo "以下系统依赖是 deploy_linux.sh 安装的："
    echo "  - Go (如果之前没有)"
    echo "  - Node.js (如果之前没有)"
    echo "  - Wails CLI"
    echo "  - Python 包"
    echo
    log_warn "警告: 卸载这些依赖可能影响其他项目！"
    echo
    
    if ! confirm "是否卸载系统依赖?" "N"; then
        log_info "跳过系统依赖卸载"
        return
    fi
    
    echo
    
    # 卸载 Wails
    if command -v wails >/dev/null 2>&1; then
        log_info "卸载 Wails CLI..."
        if [ -n "$GOPATH" ]; then
            rm -f "$GOPATH/bin/wails"
        else
            rm -f "$HOME/go/bin/wails"
        fi
        log_info "[OK] Wails 已卸载"
    fi
    
    # 清理 Go 环境变量（从 .bashrc 删除）
    if [ -f "$HOME/.bashrc" ]; then
        log_info "清理 .bashrc 中的环境变量..."
        sed -i.bak '/export.*\/usr\/local\/go\/bin/d' "$HOME/.bashrc" 2>/dev/null
        sed -i.bak '/export GOPATH=/d' "$HOME/.bashrc" 2>/dev/null
        sed -i.bak '/export GOPROXY=/d' "$HOME/.bashrc" 2>/dev/null
        sed -i.bak '/export GO111MODULE=/d' "$HOME/.bashrc" 2>/dev/null
        rm -f "$HOME/.bashrc.bak"
    fi
    
    echo
    log_info "如需完全卸载 Go 和 Node.js，请手动执行:"
    echo "  Go:      sudo rm -rf /usr/local/go"
    echo "  Node.js: sudo apt remove nodejs npm  (或使用对应的包管理器)"
    echo
}

# 显示卸载摘要
show_summary() {
    log_step "卸载摘要"
    
    echo
    echo "=========================================="
    echo "  FastMonitor 完全卸载完成"
    echo "=========================================="
    echo
    echo "统计信息:"
    echo "  已删除项目数: $REMOVED_COUNT"
    if [ $FAILED_COUNT -gt 0 ]; then
        echo "  失败项目数:   $FAILED_COUNT"
    fi
    echo
    echo "已清理的内容:"
    echo "  [OK] 编译产物 (pcap_parser, split)"
    echo "  [OK] PcapPlusPlus 文件"
    echo "  [OK] 前端构建产物 (dist, node_modules)"
    echo "  [OK] Go 构建缓存"
    echo "  [OK] Python 虚拟环境"
    echo "  [OK] 生成的脚本 (start.sh)"
    echo "  [OK] 配置文件 (config.yaml)"
    echo "  [OK] 数据文件 (data/, logs/, features/)"
    echo "  [OK] 临时文件和缓存"
    echo
    echo "保留的内容:"
    echo "  - 源代码文件"
    echo "  - Git 仓库"
    echo "  - package.json, go.mod 等配置文件"
    echo
    
    if command -v go >/dev/null 2>&1; then
        echo "系统依赖 (未卸载):"
        echo "  - Go: $(go version | awk '{print $3}')"
    fi
    if command -v node >/dev/null 2>&1; then
        echo "  - Node.js: $(node --version)"
    fi
    if command -v wails >/dev/null 2>&1; then
        echo "  - Wails: $(wails version 2>/dev/null | head -1)"
    fi
    echo
    
    log_info "项目已恢复到初始状态（保留源代码）"
    echo
    echo "如需重新部署，请运行:"
    echo "  ./deploy_linux.sh"
    echo
    echo "如需完全删除项目，请运行:"
    echo "  cd .. && rm -rf $(basename $(pwd))"
    echo
}

# 主函数
main() {
    echo
    echo "=========================================="
    echo "  FastMonitor Linux 完全卸载脚本"
    echo "=========================================="
    echo
    
    # 检查是否在项目目录
    if [ ! -f "wails.json" ] && [ ! -f "go.mod" ]; then
        log_error "当前目录不是 FastMonitor 项目目录"
        log_error "请在项目根目录运行此脚本"
        exit 1
    fi
    
    log_warn "此操作将完全清除 FastMonitor 的所有安装内容！"
    log_warn "包括: 编译产物、下载文件、配置、数据、日志等"
    echo
    
    if ! confirm "确认要完全卸载吗?" "N"; then
        log_info "已取消卸载"
        exit 0
    fi
    
    echo
    
    # 执行卸载步骤
    stop_running_processes
    remove_binaries
    remove_pcapplusplus
    remove_frontend
    remove_go_artifacts
    remove_python_venv
    remove_generated_scripts
    remove_config_files
    remove_data_files
    clean_temp_files
    
    # 可选卸载
    uninstall_system_dependencies
    
    show_summary
}

# 运行主函数
main "$@"
