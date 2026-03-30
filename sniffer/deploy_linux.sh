#!/bin/bash

#############################################################
# FastMonitor Linux 部署脚本
# 适用于: Ubuntu/Debian, CentOS/RHEL, Arch Linux
# 功能: 自动安装依赖、编译构建、配置服务
#############################################################

set -e  # 遇到错误立即退出

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

# 检查是否为root用户
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        log_warn "检测到以root用户运行，建议使用普通用户并使用sudo"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 检测Linux发行版
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        log_info "检测到操作系统: $NAME $VERSION"
    else
        log_error "无法检测操作系统类型"
        exit 1
    fi
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 安装系统依赖
install_system_dependencies() {
    log_step "安装系统依赖"
    
    case $OS in
        ubuntu|debian)
            log_info "使用apt安装依赖..."
            sudo apt update
            
            # 首先尝试安装 webkit2gtk-4.0（Wails v2 需要）
            log_info "尝试安装 webkit2gtk..."
            WEBKIT_INSTALLED=false
            
            if sudo apt install -y libwebkit2gtk-4.0-dev 2>/dev/null; then
                log_info "[OK] 已安装 webkit2gtk-4.0"
                WEBKIT_INSTALLED=true
            elif sudo apt install -y libwebkit2gtk-4.1-dev 2>/dev/null; then
                log_info "[OK] 已安装 webkit2gtk-4.1"
                log_warn "Wails v2 需要 webkit2gtk-4.0，但系统只有 4.1 版本"
                log_info "尝试创建兼容性链接..."
                
                # 查找 webkit2gtk-4.1.pc 位置
                PC_41_PATH=$(pkg-config --variable=pcfiledir webkit2gtk-4.1 2>/dev/null || echo "")
                
                if [ -n "$PC_41_PATH" ] && [ -f "$PC_41_PATH/webkit2gtk-4.1.pc" ]; then
                    log_info "找到 webkit2gtk-4.1.pc 在: $PC_41_PATH"
                    
                    # 创建符号链接
                    sudo ln -sf "$PC_41_PATH/webkit2gtk-4.1.pc" "$PC_41_PATH/webkit2gtk-4.0.pc"
                    
                    # 验证链接
                    if pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
                        log_info "[OK] 已创建 webkit2gtk-4.0 兼容性链接"
                        WEBKIT_INSTALLED=true
                    else
                        log_error "兼容性链接创建失败"
                    fi
                else
                    log_error "找不到 webkit2gtk-4.1.pc 文件"
                fi
            fi
            
            if [ "$WEBKIT_INSTALLED" != true ]; then
                log_error "无法安装或配置 webkit2gtk"
                log_error "请手动安装: sudo apt install libwebkit2gtk-4.0-dev"
                exit 1
            fi
            
            # 安装其他依赖
            sudo apt install -y \
                build-essential \
                cmake \
                libpcap-dev \
                libgtk-3-dev \
                pkg-config \
                gcc \
                g++ \
                make \
                git \
                curl \
                wget \
                sqlite3 \
                libsqlite3-dev \
                libfftw3-dev \
                ca-certificates \
                gnupg \
                lsb-release \
                python3 \
                python3-pip \
                python3-venv
            # 可选：某些环境可能没有单独的 libstdc++-static 包名
            sudo apt install -y libstdc++-static || log_warn "libstdc++-static 不可用，将继续（通常对源码编译非必须）"
            ;;
            
        centos|rhel|rocky|almalinux)
            log_info "使用yum/dnf安装依赖..."
            
            # 判断使用yum还是dnf
            if command_exists dnf; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            
            sudo $PKG_MGR install -y epel-release || true
            sudo $PKG_MGR groupinstall -y "Development Tools"
            sudo $PKG_MGR install -y \
                libpcap-devel \
                webkit2gtk3-devel \
                gtk3-devel \
                cmake \
                gcc \
                gcc-c++ \
                make \
                git \
                curl \
                wget \
                sqlite \
                sqlite-devel \
                libstdc++-static \
                python3 \
                python3-pip \
                ca-certificates
            ;;
            
        arch|manjaro)
            log_info "使用pacman安装依赖..."
            sudo pacman -Sy --noconfirm \
                base-devel \
                cmake \
                libpcap \
                webkit2gtk \
                gtk3 \
                gcc \
                make \
                git \
                curl \
                wget \
                sqlite \
                python \
                python-pip
            ;;
            
        fedora)
            log_info "使用dnf安装依赖..."
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y \
                libpcap-devel \
                webkit2gtk4.0-devel \
                gtk3-devel \
                cmake \
                gcc \
                gcc-c++ \
                make \
                git \
                curl \
                wget \
                sqlite \
                sqlite-devel \
                libstdc++-static \
                python3 \
                python3-pip
            ;;
            
        *)
            log_error "不支持的操作系统: $OS"
            log_warn "请手动安装以下依赖:"
            log_warn "  - build-essential / Development Tools"
            log_warn "  - libpcap-dev"
            log_warn "  - webkit2gtk"
            log_warn "  - gtk3"
            log_warn "  - sqlite3"
            log_warn "  - python3"
            exit 1
            ;;
    esac
    
    log_info "系统依赖安装完成"
    
    # 修复可能存在的权限问题
    log_info "检查并修复项目文件权限..."
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        # 如果是通过 sudo 运行的，将文件所有权改回原用户
        sudo chown -R $SUDO_USER:$SUDO_USER "$(pwd)"
        log_info "[OK] 文件权限已修复为用户: $SUDO_USER"
    elif [ "$(stat -c '%U' . 2>/dev/null || stat -f '%Su' .)" = "root" ] && [ "$USER" != "root" ]; then
        # 如果当前目录属于 root 但当前用户不是 root
        sudo chown -R $USER:$USER "$(pwd)"
        log_info "[OK] 文件权限已修复为用户: $USER"
    fi
}

# 安装Go
install_go() {
    log_step "检查Go环境"
    
    GO_VERSION="1.23.5"  # 可以修改为需要的版本
    GO_REQUIRED="1.22.0"
    
    # 检查Go是否已安装
    if command_exists go; then
        CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "检测到已安装Go版本: $CURRENT_GO_VERSION"
        
        # 版本比较
        if [ "$(printf '%s\n' "$GO_REQUIRED" "$CURRENT_GO_VERSION" | sort -V | head -n1)" = "$GO_REQUIRED" ]; then
            log_info "[OK] Go版本满足要求 (>= $GO_REQUIRED)"
            
            # 显示Go环境信息
            log_info "Go安装路径: $(which go)"
            if [ -n "$GOPATH" ]; then
                log_info "GOPATH: $GOPATH"
            else
                log_warn "GOPATH未设置，使用默认值: $HOME/go"
                export GOPATH=$HOME/go
            fi
            
            # 确保环境变量配置
            if [ -n "$GOPROXY" ]; then
                log_info "GOPROXY: $GOPROXY"
            else
                log_info "配置GOPROXY加速..."
                export GOPROXY=https://goproxy.cn,direct
                export GO111MODULE=on
            fi
            
            log_info "[OK] Go环境检查完成，跳过安装"
            return 0
        else
            log_warn "Go版本过低 (当前: $CURRENT_GO_VERSION, 需要: >= $GO_REQUIRED)"
            log_warn "将升级到 Go $GO_VERSION"
            
            read -p "是否继续升级Go? (Y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                log_error "Go版本不满足要求，无法继续"
                exit 1
            fi
        fi
    else
        log_info "未检测到Go，准备安装 Go $GO_VERSION"
    fi
    
    log_info "下载Go $GO_VERSION..."
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        armv7l)
            GO_ARCH="armv6l"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://golang.google.cn/dl/${GO_TARBALL}"
    
    # 下载Go
    cd /tmp
    wget -O "$GO_TARBALL" "$GO_URL" || {
        log_warn "从golang.google.cn下载失败，尝试从golang.org下载..."
        GO_URL="https://go.dev/dl/${GO_TARBALL}"
        wget -O "$GO_TARBALL" "$GO_URL"
    }
    
    # 安装Go
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    rm "$GO_TARBALL"
    
    # 配置环境变量（用户级 + 系统级，避免新终端找不到 go/wails）
    for f in "$HOME/.bashrc" "$HOME/.profile"; do
        if [ -f "$f" ] && ! grep -q "/usr/local/go/bin" "$f"; then
            {
                echo ''
                echo '# FastMonitor: Go & Wails PATH'
                echo 'export GOPATH="$HOME/go"'
                echo 'export PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"'
            } >> "$f"
        fi
    done

    # 系统级：让所有 shell/session 都能拿到 PATH（需要 sudo）
    sudo tee /etc/profile.d/fastmonitor-go.sh >/dev/null <<'EOF'
# FastMonitor: Go & Wails PATH
export GOPATH="$HOME/go"
export PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"
EOF
    sudo chmod 0644 /etc/profile.d/fastmonitor-go.sh || true
    
    # 配置Go代理（中国大陆加速）
    if ! grep -q "GOPROXY" ~/.bashrc; then
        echo 'export GOPROXY=https://goproxy.cn,direct' >> ~/.bashrc
        echo 'export GO111MODULE=on' >> ~/.bashrc
    fi
    
    export GOPATH=$HOME/go
    export PATH=/usr/local/go/bin:$GOPATH/bin:$PATH
    export GOPROXY=https://goproxy.cn,direct
    export GO111MODULE=on
    
    # 切回项目根目录
    cd "$PROJECT_ROOT"
    
    log_info "Go安装完成: $(go version)"
}

# 安装Node.js和npm
install_nodejs() {
    log_step "检查Node.js环境"
    
    NODE_VERSION="20"  # LTS版本
    NODE_REQUIRED="18"
    
    # 检查Node.js是否已安装
    if command_exists node; then
        CURRENT_NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
        FULL_NODE_VERSION=$(node --version | sed 's/v//')
        log_info "检测到已安装Node.js版本: v$FULL_NODE_VERSION"
        
        if [ "$CURRENT_NODE_VERSION" -ge "$NODE_REQUIRED" ]; then
            log_info "[OK] Node.js版本满足要求 (>= v${NODE_REQUIRED})"
            log_info "Node.js路径: $(which node)"
            
            if command_exists npm; then
                log_info "npm版本: $(npm --version)"
            else
                log_error "未找到npm，请重新安装Node.js"
                exit 1
            fi
            
            # 检查npm镜像配置
            NPM_REGISTRY=$(npm config get registry)
            if [[ "$NPM_REGISTRY" == *"npmmirror"* ]] || [[ "$NPM_REGISTRY" == *"taobao"* ]]; then
                log_info "npm镜像: $NPM_REGISTRY"
            else
                log_info "配置npm国内镜像加速..."
                npm config set registry https://registry.npmmirror.com
            fi
            
            log_info "[OK] Node.js环境检查完成，跳过安装"
            return 0
        else
            log_warn "Node.js版本过低 (当前: v$FULL_NODE_VERSION, 需要: >= v${NODE_REQUIRED})"
            log_warn "将升级到 Node.js $NODE_VERSION LTS"
            
            read -p "是否继续升级Node.js? (Y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                log_error "Node.js版本不满足要求，无法继续"
                exit 1
            fi
        fi
    else
        log_info "未检测到Node.js，准备安装 Node.js $NODE_VERSION LTS"
    fi
    
    log_info "通过NodeSource安装Node.js $NODE_VERSION..."
    
    # 使用NodeSource安装最新LTS版本
    case $OS in
        ubuntu|debian)
            curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
            sudo apt install -y nodejs
            ;;
            
        centos|rhel|rocky|almalinux|fedora)
            curl -fsSL https://rpm.nodesource.com/setup_${NODE_VERSION}.x | sudo bash -
            if command_exists dnf; then
                sudo dnf install -y nodejs
            else
                sudo yum install -y nodejs
            fi
            ;;
            
        arch|manjaro)
            sudo pacman -Sy --noconfirm nodejs npm
            ;;
            
        *)
            log_error "不支持的操作系统，请手动安装Node.js 18+"
            exit 1
            ;;
    esac
    
    # 配置npm国内镜像加速
    npm config set registry https://registry.npmmirror.com
    
    log_info "Node.js安装完成: $(node --version)"
    log_info "npm版本: $(npm --version)"
}

# 安装Wails
install_wails() {
    log_step "检查Wails CLI"
    
    # 检查Wails是否已安装
    if command_exists wails; then
        CURRENT_WAILS_VERSION=$(wails version 2>/dev/null | grep -oP 'v\K[0-9.]+' | head -1)
        
        if [ -n "$CURRENT_WAILS_VERSION" ]; then
            log_info "[OK] 检测到已安装Wails版本: v$CURRENT_WAILS_VERSION"
            log_info "Wails路径: $(which wails)"
            log_info "[OK] Wails环境检查完成，跳过安装"
            log_info "提示：如需更新Wails，请运行:"
            log_info "  go install github.com/wailsapp/wails/v2/cmd/wails@latest"
            return 0
        fi
    fi
    
    log_info "未检测到Wails CLI，准备安装..."
    
    # 确保Go已安装
    if ! command_exists go; then
        log_error "未找到Go，无法安装Wails"
        exit 1
    fi
    
    log_info "通过go install安装Wails v2..."
    go install github.com/wailsapp/wails/v2/cmd/wails@latest
    
    # 确保$GOPATH/bin在PATH中
    if [ -z "$GOPATH" ]; then
        export GOPATH=$HOME/go
    fi
    export PATH=$PATH:$GOPATH/bin
    
    # 验证安装
    if command_exists wails; then
        log_info "[OK] Wails安装完成: $(wails version)"
    else
        log_error "Wails安装失败，请检查Go环境和网络连接"
        log_error "您也可以手动安装: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        exit 1
    fi
}

# 安装Python依赖（用于domain分类功能）
install_python_dependencies() {
    log_step "安装Python依赖"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    if [ ! -f "domain/requirements.txt" ]; then
        log_info "未找到domain/requirements.txt，跳过Python依赖安装"
        log_warn "如需使用domain分类功能，请手动安装相关依赖"
        return
    fi
    
    log_info "检测到domain/requirements.txt，准备安装Python依赖..."
    
    # 检查Python3是否可用
    if ! command_exists python3; then
        log_error "未找到python3，无法安装Python依赖"
        return 1
    fi
    
    # 创建虚拟环境目录
    VENV_DIR="domain/venv"
    
    if [ -d "$VENV_DIR" ]; then
        log_info "检测到已存在的虚拟环境: $VENV_DIR"
    else
        log_info "创建Python虚拟环境: $VENV_DIR"
        
        # 确保python3-venv已安装
        if ! python3 -m venv --help > /dev/null 2>&1; then
            log_warn "python3-venv未安装，尝试安装..."
            case $OS in
                ubuntu|debian)
                    sudo apt install -y python3-venv python3-full
                    ;;
                centos|rhel|rocky|almalinux|fedora)
                    sudo yum install -y python3-virtualenv || sudo dnf install -y python3-virtualenv
                    ;;
                arch|manjaro)
                    # Arch Linux的python包自带venv
                    log_info "Arch Linux自带venv支持"
                    ;;
            esac
        fi
        
        # 创建虚拟环境
        python3 -m venv "$VENV_DIR" || {
            log_error "创建虚拟环境失败"
            return 1
        }
        
        log_info "[OK] 虚拟环境创建成功"
    fi
    
    # 激活虚拟环境并安装依赖
    log_info "在虚拟环境中安装Python依赖..."
    
    # 使用虚拟环境的pip安装
    "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel || {
        log_warn "pip升级失败，继续安装依赖..."
    }
    
    "$VENV_DIR/bin/pip" install -r domain/requirements.txt || {
        log_error "Python依赖安装失败"
        log_warn "这不会影响主程序运行，但domain分类功能可能不可用"
        log_warn "您可以稍后手动安装:"
        log_warn "  source domain/venv/bin/activate"
        log_warn "  pip install -r domain/requirements.txt"
        return 1
    }
    
    log_info "[OK] Python依赖安装完成"
}

# 下载和配置 PcapPlusPlus
build_pcapplusplus_from_source() {
    log_step "预编译包不可用，编译 PcapPlusPlus 源码（兜底）"

    if [ -z "${PCAP_VERSION:-}" ]; then
        log_error "PCAP_VERSION 未设置"
        exit 1
    fi
    if [ -z "${PCAP_ARCH:-}" ]; then
        log_error "PCAP_ARCH 未设置"
        exit 1
    fi

    PCAP_DIR_NAME="pcapplusplus-source-${PCAP_VERSION}-${PCAP_ARCH}-${PCAP_GCC}"
    export PCAP_ROOT="$PROJECT_ROOT/$PCAP_DIR_NAME"

    log_info "PcapPlusPlus 源码安装目录: $PCAP_ROOT"
    rm -rf "$PCAP_ROOT" || true
    mkdir -p "$PCAP_ROOT"

    TMP_DIR="$(mktemp -d)"
    SRC_URL="https://github.com/seladb/PcapPlusPlus/archive/refs/tags/v${PCAP_VERSION}.tar.gz"
    SRC_TARBALL="${TMP_DIR}/pcapplusplus-src.tar.gz"

    log_info "下载源码: $SRC_URL"
    if ! wget "$SRC_URL" -O "$SRC_TARBALL"; then
        log_warn "wget 下载失败，尝试 curl..."
        if command -v curl >/dev/null 2>&1; then
            if ! curl -L "$SRC_URL" -o "$SRC_TARBALL"; then
                log_error "下载 PcapPlusPlus 源码失败（wget/curl 均失败）: $SRC_URL"
                rm -rf "$TMP_DIR" || true
                exit 1
            fi
        else
            log_error "wget 下载失败且未找到 curl，无法下载源码: $SRC_URL"
            rm -rf "$TMP_DIR" || true
            exit 1
        fi
    fi

    log_info "解压源码..."
    tar -xzf "$SRC_TARBALL" -C "$TMP_DIR" || {
        log_error "解压源码失败"
        rm -rf "$TMP_DIR" || true
        exit 1
    }

    # 找到解压出来的目录名（一般形如 PcapPlusPlus-v25.05）
    SRC_DIR=""
    for d in "$TMP_DIR"/PcapPlusPlus-*; do
        if [ -d "$d" ]; then
            SRC_DIR="$d"
            break
        fi
    done
    if [ -z "$SRC_DIR" ]; then
        log_error "无法定位源码目录（解压结果不符合预期）"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi

    log_info "源码目录: $SRC_DIR"
    cd "$SRC_DIR"

    # 只构建需要的库（Common++ / Packet++ / Pcap++），并安装到 $PCAP_ROOT
    # 禁用 examples/tests 以加快编译速度。
    if ! cmake -S . -B build \
        -DPCAPPP_BUILD_EXAMPLES=OFF \
        -DPCAPPP_BUILD_TESTS=OFF \
        -DPCAPPP_BUILD_TUTORIALS=OFF \
        -DPCAPPP_INSTALL=ON \
        -DPCAPPP_BUILD_PCAPPP=ON \
        -DCMAKE_BUILD_TYPE=Release; then
        log_error "cmake 配置失败"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi

    log_info "开始编译 PcapPlusPlus（libs only）..."
    if ! cmake --build build -j"$(nproc)"; then
        log_error "PcapPlusPlus 编译失败"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi

    log_info "安装到: $PCAP_ROOT"
    if ! cmake --install build --prefix "$PCAP_ROOT"; then
        log_error "PcapPlusPlus 安装失败"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi

    # 基本校验：确保安装出了需要的静态库
    if [ ! -f "$PCAP_ROOT/lib/libCommon++.a" ] || [ ! -f "$PCAP_ROOT/lib/libPacket++.a" ] || [ ! -f "$PCAP_ROOT/lib/libPcap++.a" ]; then
        log_error "安装校验失败：未找到期望的静态库（libCommon++/libPacket++/libPcap++）"
        log_error "请检查 $PCAP_ROOT/lib 下实际文件。"
        rm -rf "$TMP_DIR" || true
        exit 1
    fi

    rm -rf "$TMP_DIR" || true
    log_info "PcapPlusPlus 编译/安装完成: $PCAP_ROOT"
}

setup_pcapplusplus() {
    log_step "下载和配置 PcapPlusPlus"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            PCAP_ARCH="x86_64"
            PCAP_GCC="gcc-13.3.0"
            ;;
        aarch64|arm64)
            PCAP_ARCH="aarch64"
            PCAP_GCC="gcc-13.3.0"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    # Ubuntu版本检测
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        # 从系统 VERSION_ID 推导 ubuntu x.y 版本（例如 22.04/24.04）
        # VERSION_ID 可能是类似 22.04 或 22.04.3，这里取前两段。
        UBUNTU_VER_RAW="${VERSION_ID:-}"
        UBUNTU_VER="$(echo "$UBUNTU_VER_RAW" | awk -F. '{print $1"."$2}')"
    else
        UBUNTU_VER=""
    fi

    # 兜底：如果无法解析到 ubuntu x.y，则回退到 24.04（可能因 glibc 不匹配而导致运行失败）
    if [ -z "$UBUNTU_VER" ]; then
        UBUNTU_VER="24.04"
        log_warn "无法从 /etc/os-release 解析 VERSION_ID，将回退使用 UBUNTU_VER=$UBUNTU_VER"
    else
        log_info "检测到 Ubuntu VERSION_ID=$UBUNTU_VER_RAW，使用 PcapPlusPlus 包版本 UBUNTU_VER=$UBUNTU_VER"
    fi
    
    PCAP_VERSION="25.05"

    # 优先下载匹配包；如果匹配包不存在，尝试下载“更低版本的 Ubuntu 包”（通常能兼容更高 glibc）
    UBUNTU_CANDIDATES=("$UBUNTU_VER")
    case "$UBUNTU_VER" in
        "24.04") ;;
        "23.10") UBUNTU_CANDIDATES+=("23.04" "22.04" "20.04") ;;
        "22.04") UBUNTU_CANDIDATES+=("20.04" "18.04") ;;
        "20.04") UBUNTU_CANDIDATES+=("18.04") ;;
        *) ;;
    esac

    # 架构名兜底：有些构建资产可能用 arm64 命名
    PCAP_ARCH_CANDIDATES=("$PCAP_ARCH")
    if [ "$PCAP_ARCH" = "aarch64" ]; then
        PCAP_ARCH_CANDIDATES=("aarch64" "arm64")
    fi

    FOUND_PCAPPLUSPLUS="0"
    PCAP_DIR_NAME=""

    for u in "${UBUNTU_CANDIDATES[@]}"; do
        for arch in "${PCAP_ARCH_CANDIDATES[@]}"; do
            PCAP_ORIGINAL_DIR="pcapplusplus-${PCAP_VERSION}-ubuntu-${u}-${PCAP_GCC}-${arch}"
            # 不同 Ubuntu 版本使用不同目录，避免把旧产物混用到后续编译里
            PCAP_DIR_NAME="pcapplusplus${PCAP_VERSION}-ubuntu-${u}-${PCAP_GCC}-${arch}"
            PCAP_TARBALL="${PCAP_ORIGINAL_DIR}.tar.gz"
            PCAP_URL="https://github.com/seladb/PcapPlusPlus/releases/download/v${PCAP_VERSION}/${PCAP_TARBALL}"

            if [ -d "$PCAP_DIR_NAME" ]; then
                log_info "PcapPlusPlus 目录已存在: $PCAP_DIR_NAME"
                FOUND_PCAPPLUSPLUS="1"
                break 2
            fi

            log_info "尝试下载 PcapPlusPlus: $PCAP_URL"
            rm -f "$PCAP_TARBALL" 2>/dev/null || true

            if wget "$PCAP_URL" -O "$PCAP_TARBALL"; then
                log_info "[OK] 下载成功，解压 PcapPlusPlus..."
                if ! tar -xzf "$PCAP_TARBALL"; then
                    log_warn "解压失败：$PCAP_TARBALL，继续尝试下一个候选"
                    rm -f "$PCAP_TARBALL" 2>/dev/null || true
                    continue
                fi

                log_info "[OK] PcapPlusPlus 已解压到: $PCAP_ORIGINAL_DIR"
                log_info "重命名目录: $PCAP_ORIGINAL_DIR -> $PCAP_DIR_NAME"
                if ! mv "$PCAP_ORIGINAL_DIR" "$PCAP_DIR_NAME"; then
                    log_error "重命名目录失败：$PCAP_ORIGINAL_DIR -> $PCAP_DIR_NAME"
                    exit 1
                fi
                rm -f "$PCAP_TARBALL" || true

                FOUND_PCAPPLUSPLUS="1"
                break 2
            else
                log_warn "下载失败：$PCAP_URL"
                rm -f "$PCAP_TARBALL" 2>/dev/null || true
            fi
        done
    done

    if [ "$FOUND_PCAPPLUSPLUS" != "1" ] || [ -z "$PCAP_DIR_NAME" ]; then
        log_error "未能下载到适用于当前系统的 PcapPlusPlus 预编译包。"
        log_error "将自动切换到从源码编译（可能耗时较长）"
        build_pcapplusplus_from_source
    fi

    # 记录路径供后续使用（使用绝对路径）
    export PCAP_ROOT="$PROJECT_ROOT/$PCAP_DIR_NAME"
    log_info "PcapPlusPlus 根目录: $PCAP_ROOT"
}

# 编译 lzprobe
compile_lzprobe() {
    log_step "编译 lzprobe (pcap_parser)"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    if [ -z "$PCAP_ROOT" ]; then
        log_error "PCAP_ROOT 未设置，请先运行 setup_pcapplusplus"
        exit 1
    fi
    
    if [ ! -d "lzprobe" ]; then
        log_warn "未找到 lzprobe 目录，跳过编译"
        return
    fi
    
    cd lzprobe
    
    log_info "更新 Makefile 中的 PcapPlusPlus 路径..."
    
    # 备份原始 Makefile
    if [ ! -f "Makefile.bak" ]; then
        cp Makefile Makefile.bak
    fi
    
    # 创建临时 Makefile，更新路径
    cat > Makefile.tmp <<EOF
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -g \\
            -I${PCAP_ROOT}/include \\
            -I./include

LDFLAGS  := -L${PCAP_ROOT}/lib \\
            -lPacket++ -lPcap++ -lCommon++ -lpcap -lpthread -lfftw3

SRC_DIRS := src src/utils src/parsers
BUILD_DIR := build

# main program source files
MAIN_SRCS := main.cpp \$(foreach dir,\$(SRC_DIRS),\$(wildcard \$(dir)/*.cpp))
MAIN_OBJS := \$(patsubst %.cpp,\$(BUILD_DIR)/%.o,\$(MAIN_SRCS))

TARGET := pcap_parser

all: \$(TARGET)

\$(TARGET): \$(MAIN_OBJS)
	@echo "Linking \$@ ..."
	\$(CXX) -o \$@ \$^ \$(LDFLAGS)

\$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p \$(dir \$@)
	\$(CXX) \$(CXXFLAGS) -c \$< -o \$@

clean:
	rm -rf \$(BUILD_DIR) \$(TARGET)

.PHONY: all clean
EOF
    
    mv Makefile.tmp Makefile
    
    log_info "编译 pcap_parser..."
    make clean || true
    make -j$(nproc) || {
        log_error "编译 pcap_parser 失败"
        # 恢复备份
        if [ -f "Makefile.bak" ]; then
            mv Makefile.bak Makefile
        fi
        cd ..
        exit 1
    }
    
    # 检查编译产物
    if [ ! -f "pcap_parser" ]; then
        log_error "pcap_parser 未生成"
        cd ..
        exit 1
    fi
    
    # 移动到项目根目录
    log_info "移动 pcap_parser 到项目根目录..."
    mv pcap_parser ../
    
    cd ..
    
    log_info "[OK] pcap_parser 编译完成: $(pwd)/pcap_parser"
}

# 编译 domain/split.cpp
compile_domain_split() {
    log_step "编译 domain/split"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    if [ -z "$PCAP_ROOT" ]; then
        log_error "PCAP_ROOT 未设置，请先运行 setup_pcapplusplus"
        exit 1
    fi
    
    if [ ! -f "domain/split.cpp" ]; then
        log_warn "未找到 domain/split.cpp，跳过编译"
        return
    fi
    
    cd domain
    
    log_info "编译 split.cpp..."
    g++ -std=c++17 -O2 -Wall \
        -I${PCAP_ROOT}/include \
        -L${PCAP_ROOT}/lib \
        -o split split.cpp \
        -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -lsqlite3 || {
        log_error "编译 split 失败"
        cd ..
        exit 1
    }
    
    # 检查编译产物
    if [ ! -f "split" ]; then
        log_error "split 未生成"
        cd ..
        exit 1
    fi
    
    chmod +x split
    
    cd ..
    
    log_info "[OK] split 编译完成: $(pwd)/domain/split"
}

# 构建前端
build_frontend() {
    log_step "构建前端项目"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    if [ ! -d "frontend" ]; then
        log_error "未找到 frontend 目录"
        log_error "当前目录: $(pwd)"
        exit 1
    fi
    
    cd frontend
    
    if [ ! -f "package.json" ]; then
        log_error "未找到frontend/package.json"
        exit 1
    fi
    
    # 检查并修复 dist 目录权限
    if [ -d "dist" ]; then
        log_info "检查 dist 目录权限..."
        if [ ! -w "dist" ] || ! rm -rf dist/test_permission_check 2>/dev/null; then
            log_warn "dist 目录存在权限问题，尝试修复..."
            
            # 尝试修改权限
            chmod -R u+w dist 2>/dev/null || true
            
            # 如果还是无法删除，使用 sudo
            if ! rm -rf dist 2>/dev/null; then
                log_warn "需要 sudo 权限清理 dist 目录"
                sudo rm -rf dist || {
                    log_error "无法清理 dist 目录"
                    cd ..
                    exit 1
                }
                log_info "[OK] 已清理 dist 目录"
            fi
        fi
    fi
    
    # 检查并修复 node_modules 权限（如果存在）
    if [ -d "node_modules" ]; then
        if [ ! -w "node_modules" ]; then
            log_info "修复 node_modules 权限..."
            chmod -R u+w node_modules 2>/dev/null || sudo chown -R $USER:$USER node_modules 2>/dev/null || true
        fi
    fi
    
    log_info "安装npm依赖..."
    npm install
    
    log_info "构建前端..."
    npm run build
    
    if [ ! -d "dist" ]; then
        log_error "前端构建失败，未生成dist目录"
        exit 1
    fi
    
    # 确保新生成的 dist 目录属于当前用户
    if [ -n "$USER" ] && [ "$USER" != "root" ]; then
        chown -R $USER:$USER dist 2>/dev/null || true
    fi
    
    cd ..
    log_info "前端构建完成"
}

# 构建后端
build_backend() {
    log_step "构建Go后端"
    
    # 确保在项目根目录
    cd "$PROJECT_ROOT"
    
    # 检测并设置架构相关的环境变量
    ARCH=$(uname -m)
    log_info "系统架构: $ARCH"
    
    # 为非x86_64架构设置CGO参数
    if [[ "$ARCH" != "x86_64" ]]; then
        log_info "非x86_64架构，配置CGO编译参数..."
        
        export CGO_ENABLED=1
        export CGO_CFLAGS="-g -O2"
        export CGO_CPPFLAGS=""
        export CGO_CXXFLAGS="-g -O2"
        export CGO_LDFLAGS=""
        
        # 对于Go编译器，明确设置架构
        case $ARCH in
            aarch64|arm64)
                export GOARCH=arm64
                ;;
            armv7l)
                export GOARCH=arm
                export GOARM=7
                ;;
            armv6l)
                export GOARCH=arm
                export GOARM=6
                ;;
        esac
        
        log_info "已设置环境变量："
        log_info "  GOARCH=$GOARCH"
        log_info "  CGO_ENABLED=$CGO_ENABLED"
        log_info "  CGO_CFLAGS=$CGO_CFLAGS"
    fi
    
    log_info "下载Go模块依赖..."
    go mod download
    
    log_info "整理依赖..."
    go mod tidy
    
    log_info "验证依赖..."
    go mod verify
    
    log_info "Go依赖准备完成"
}

# 准备Wails环境（不构建，使用dev模式）
prepare_wails() {
    log_step "准备Wails开发环境"
    
    # 检查wails.json配置
    if [ ! -f "wails.json" ]; then
        log_error "未找到wails.json配置文件"
        exit 1
    fi
    
    # 检测系统架构
    ARCH=$(uname -m)
    log_info "检测到系统架构: $ARCH"
    
    # 为非x86_64架构设置CGO环境变量
    if [[ "$ARCH" != "x86_64" ]]; then
        log_info "为 $ARCH 架构设置 CGO 参数..."
        export CGO_ENABLED=1
        export CGO_CFLAGS="-g -O2"
        export CGO_LDFLAGS=""
        
        case $ARCH in
            aarch64|arm64)
                export GOARCH=arm64
                ;;
            armv7l)
                export GOARCH=arm
                export GOARM=7
                ;;
            armv6l)
                export GOARCH=arm
                export GOARM=6
                ;;
        esac
    fi
    
    log_info "[OK] Wails环境准备完成"
    log_info ""
    log_info "注意：本项目使用 wails dev 开发模式运行"
    log_info "这样可以避免复杂的构建问题，并支持热更新"
}

# 创建配置文件
create_config() {
    log_step "创建配置文件"
    
    if [ ! -f "config.yaml" ]; then
        log_info "创建默认config.yaml..."
        cat > config.yaml <<EOF
capture:
  device: ""                           # 留空自动选择，或指定网卡名称如 "eth0"
  bpf_filter: ""                       # BPF过滤器，如 "tcp or udp"
  promiscuous: true                    # 混杂模式
  snaplen: 65535                       # 捕获长度
  buffer_size: 10485760               # 10MB缓冲区

storage:
  db_path: "./data/sniffer.db"        # SQLite数据库路径
  pcap_dir: "./data/pcap"             # PCAP文件保存目录
  pcap_rotation: "1h"                 # PCAP轮转周期: 1h, 24h等
  retention_days: 7                    # 数据保留天数
  auto_cleanup: true                   # 自动清理过期数据

performance:
  ring_buffer_size: 10000             # 环形缓冲区大小
  batch_insert_size: 100              # 批量插入大小
  refresh_interval: 2000              # 前端刷新间隔(毫秒)
  max_memory_mb: 512                  # 最大内存使用(MB)

alert:
  enabled: true                        # 启用告警
  min_level: "warning"                # 最低告警级别: info/warning/critical
  notification: false                  # 桌面通知(Linux需要libnotify)

server:
  host: "127.0.0.1"                   # 监听地址
  port: 8080                          # HTTP端口（如果有web模式）

log:
  level: "info"                       # 日志级别: debug/info/warn/error
  file: "./logs/fastmonitor.log"     # 日志文件路径
  max_size_mb: 100                    # 单个日志文件最大大小
  max_backups: 3                      # 保留的旧日志文件数
  max_age_days: 30                    # 日志文件保留天数
EOF
        log_info "已创建默认配置文件: config.yaml"
    else
        log_info "配置文件已存在，跳过创建"
    fi
}

# 创建数据目录
create_directories() {
    log_step "创建数据目录"
    
    mkdir -p data/pcap
    mkdir -p logs
    
    log_info "数据目录创建完成"
}

# 创建启动脚本
create_start_script() {
    log_step "创建启动脚本"
    
    cat > start.sh <<'EOF'
#!/bin/bash

# FastMonitor 启动脚本（使用 wails dev 模式）

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  FastMonitor 启动${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# 检查 wails 命令
if ! command -v wails &> /dev/null; then
    echo "错误: 未找到 wails 命令"
    echo "请先运行部署脚本: ./deploy_linux.sh"
    exit 1
fi

# 检查 wails.json
if [ ! -f "wails.json" ]; then
    echo "错误: 未找到 wails.json 配置文件"
    exit 1
fi

# 检查前端目录
if [ ! -d "frontend" ]; then
    echo "错误: 未找到 frontend 目录"
    exit 1
fi

# 检查权限提示
if [ ! -r /proc/net/dev ] 2>/dev/null; then
    echo -e "${YELLOW}警告: 可能需要root权限来监控网络${NC}"
    echo -e "${YELLOW}如果程序无法捕获网络数据包，请使用 sudo 运行此脚本${NC}"
    echo
fi

echo "启动 FastMonitor (wails dev 模式)..."
echo "提示: 按 Ctrl+C 停止程序"
echo

# 使用 wails dev 启动（支持热更新）
sudo env "PATH=$PATH" wails dev

EOF
    
    chmod +x start.sh
    log_info "[OK] 启动脚本创建完成: ./start.sh"
}

# 显示完成信息
show_completion_info() {
    log_step "部署完成！"
    
    echo
    echo "=========================================="
    echo "  FastMonitor 部署成功！"
    echo "=========================================="
    echo
    echo "项目目录:   $(pwd)"
    echo "配置文件:   $(pwd)/config.yaml"
    echo "数据目录:   $(pwd)/data/"
    echo "日志目录:   $(pwd)/logs/"
    echo
    echo "启动方式: ./start.sh"
    echo
}

# 环境预检查
pre_check() {
    log_step "环境预检查"
    
    echo "正在检查系统环境..."
    echo
    
    # 检查Go
    if command_exists go; then
        GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
        echo "  [OK] Go:      已安装 (v$GO_VER)"
    else
        echo "  [X] Go:      未安装"
    fi
    
    # 检查Node.js
    if command_exists node; then
        NODE_VER=$(node --version)
        echo "  [OK] Node.js: 已安装 ($NODE_VER)"
    else
        echo "  [X] Node.js: 未安装"
    fi
    
    # 检查Wails
    if command_exists wails; then
        WAILS_VER=$(wails version 2>/dev/null | grep -oP 'v\K[0-9.]+' | head -1)
        echo "  [OK] Wails:   已安装 (v$WAILS_VER)"
    else
        echo "  [X] Wails:   未安装"
    fi
    
    # 检查libpcap
    if ldconfig -p 2>/dev/null | grep -q libpcap || [ -f /usr/lib/libpcap.so ] || [ -f /usr/lib64/libpcap.so ]; then
        echo "  [OK] libpcap: 已安装"
    else
        echo "  [X] libpcap: 未安装"
    fi
    
    # 检查Python
    if command_exists python3; then
        PY_VER=$(python3 --version | awk '{print $2}')
        echo "  [OK] Python:  已安装 (v$PY_VER)"
    else
        echo "  [X] Python:  未安装"
    fi
    
    echo
    log_info "预检查完成，脚本将自动安装缺失的依赖"
    echo
    
    read -p "按 Enter 继续，或 Ctrl+C 取消..." 
    echo
}

# 检查并修复项目权限
fix_project_permissions() {
    log_step "检查项目权限"
    
    # 检查关键目录的写权限
    local need_fix=false
    local dirs_to_check=("frontend/dist" "frontend/node_modules" "data" "logs" "domain/output")
    
    for dir in "${dirs_to_check[@]}"; do
        if [ -d "$dir" ] && [ ! -w "$dir" ]; then
            log_warn "目录 $dir 没有写权限"
            need_fix=true
        fi
    done
    
    # 检查是否有属于 root 的文件
    if find . -maxdepth 3 -user root 2>/dev/null | grep -q .; then
        log_warn "检测到属于 root 用户的文件"
        need_fix=true
    fi
    
    if [ "$need_fix" = true ]; then
        echo ""
        log_warn "发现权限问题，建议修复以避免后续错误"
        echo ""
        read -p "是否自动修复权限? 需要 sudo (Y/n): " -n 1 -r
        echo
        
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            log_info "修复项目文件权限..."
            
            # 修复所有权
            sudo chown -R $USER:$USER . 2>/dev/null || log_warn "部分文件权限修复失败"
            
            # 确保目录可写
            chmod -R u+w . 2>/dev/null || log_warn "部分目录权限修复失败"
            
            log_info "[OK] 权限修复完成"
        else
            log_warn "跳过权限修复，后续可能遇到权限错误"
        fi
        echo ""
    else
        log_info "[OK] 项目权限正常"
    fi
}

# 主函数
main() {
    echo
    echo "=========================================="
    echo "  FastMonitor Linux 自动部署脚本"
    echo "=========================================="
    echo
    
    # 保存项目根目录
    PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    export PROJECT_ROOT
    cd "$PROJECT_ROOT"
    
    log_info "项目根目录: $PROJECT_ROOT"
    echo
    
    # 记录开始时间
    START_TIME=$(date +%s)
    
    # 执行部署步骤
    check_root
    detect_os
    fix_project_permissions
    pre_check
    install_system_dependencies
    install_go
    install_nodejs
    install_wails
    install_python_dependencies
    create_config
    create_directories
    build_frontend
    build_backend
    prepare_wails
    
    # 添加 PcapPlusPlus 相关编译
    setup_pcapplusplus
    compile_lzprobe
    compile_domain_split
    
    create_start_script
    
    # 计算耗时
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    echo
    log_info "总耗时: ${ELAPSED}秒"
    
    show_completion_info
}

# 错误处理
trap 'log_error "部署过程中发生错误，请检查上述日志"; exit 1' ERR

# 运行主函数
main "$@"

