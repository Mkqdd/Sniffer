#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/PacketUtils.h>
#include <sqlite3.h>

namespace fs = std::filesystem;

// 流的五元组标识
struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    FlowKey(const std::string& s_ip, const std::string& d_ip, 
            uint16_t s_port, uint16_t d_port, uint8_t proto) {
        // 统一排序，确保双向流使用相同的 key
        if (s_ip < d_ip || (s_ip == d_ip && s_port < d_port)) {
            src_ip = s_ip;
            dst_ip = d_ip;
            src_port = s_port;
            dst_port = d_port;
        } else {
            src_ip = d_ip;
            dst_ip = s_ip;
            src_port = d_port;
            dst_port = s_port;
        }
        protocol = proto;
    }
    
    bool operator<(const FlowKey& other) const {
        if (src_ip != other.src_ip) return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
        if (src_port != other.src_port) return src_port < other.src_port;
        if (dst_port != other.dst_port) return dst_port < other.dst_port;
        return protocol < other.protocol;
    }
    
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    std::string toString() const {
        return src_ip + "_" + dst_ip;
    }
};

// 用于 unordered_map 的哈希函数
struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        return std::hash<std::string>()(key.src_ip) ^
               (std::hash<std::string>()(key.dst_ip) << 1) ^
               (std::hash<uint16_t>()(key.src_port) << 2) ^
               (std::hash<uint16_t>()(key.dst_port) << 3) ^
               (std::hash<uint8_t>()(key.protocol) << 4);
    }
};

// SQLite 数据库管理类
class DatabaseManager {
private:
    sqlite3* db;
    std::string db_path;
    
public:
    DatabaseManager(const std::string& path) : db(nullptr), db_path(path) {}
    
    ~DatabaseManager() {
        close();
    }
    
    bool open() {
        int rc = sqlite3_open(db_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            std::cerr << "无法打开数据库: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        
        // 启用 WAL 模式以提高并发性能
        char* err_msg = nullptr;
        rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "设置 WAL 模式失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
        }
        
        // 创建表结构（如果不存在）
        if (!createTables()) {
            std::cerr << "创建数据库表失败" << std::endl;
            return false;
        }
        
        return true;
    }
    
    // 创建数据库表结构
    bool createTables() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS dns_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                domain TEXT,
                query_type TEXT,
                response_ip TEXT,
                payload_size INTEGER,
                ttl DATETIME NOT NULL,
                process_pid INTEGER,
                process_name TEXT,
                process_exe TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_sessions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_ttl ON dns_sessions(ttl);
            CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_sessions(domain);
            
            CREATE TABLE IF NOT EXISTS http_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                method TEXT,
                host TEXT,
                path TEXT,
                status_code INTEGER,
                user_agent TEXT,
                content_type TEXT,
                post_data TEXT,
                payload_size INTEGER,
                ttl DATETIME NOT NULL,
                process_pid INTEGER,
                process_name TEXT,
                process_exe TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_sessions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_http_ttl ON http_sessions(ttl);
            CREATE INDEX IF NOT EXISTS idx_http_host ON http_sessions(host);
            
            CREATE TABLE IF NOT EXISTS icmp_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT,
                icmp_type INTEGER,
                icmp_code INTEGER,
                icmp_seq INTEGER,
                payload_size INTEGER,
                ttl DATETIME NOT NULL,
                process_pid INTEGER,
                process_name TEXT,
                process_exe TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_icmp_timestamp ON icmp_sessions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_icmp_ttl ON icmp_sessions(ttl);
            
            CREATE TABLE IF NOT EXISTS session_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                packet_count INTEGER DEFAULT 1,
                bytes_count INTEGER DEFAULT 0,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                session_type TEXT,
                process_pid INTEGER,
                process_name TEXT,
                process_exe TEXT,
                UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
            );
            
            CREATE INDEX IF NOT EXISTS idx_flows_first_seen ON session_flows(first_seen);
            CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON session_flows(last_seen);
            CREATE INDEX IF NOT EXISTS idx_flows_protocol ON session_flows(protocol);
            CREATE INDEX IF NOT EXISTS idx_flows_process ON session_flows(process_name);
            
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                condition_field TEXT NOT NULL,
                condition_operator TEXT NOT NULL,
                condition_value TEXT NOT NULL,
                alert_level TEXT DEFAULT 'warning',
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);
            CREATE INDEX IF NOT EXISTS idx_alert_rules_type ON alert_rules(rule_type);
            
            CREATE TABLE IF NOT EXISTS alert_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                alert_level TEXT NOT NULL,
                triggered_at DATETIME NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                domain TEXT,
                url TEXT,
                details TEXT,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at DATETIME,
                acknowledged_by TEXT,
                trigger_count INTEGER DEFAULT 1,
                last_triggered_at DATETIME,
                FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_alert_logs_triggered_at ON alert_logs(triggered_at);
            CREATE INDEX IF NOT EXISTS idx_alert_logs_rule_id ON alert_logs(rule_id);
            CREATE INDEX IF NOT EXISTS idx_alert_logs_acknowledged ON alert_logs(acknowledged);
            CREATE INDEX IF NOT EXISTS idx_alert_logs_level ON alert_logs(alert_level);
            
            CREATE TABLE IF NOT EXISTS process_stats (
                name TEXT NOT NULL,
                username TEXT,
                packets_sent INTEGER DEFAULT 0,
                packets_recv INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                connections INTEGER DEFAULT 0,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                UNIQUE(name, username)
            );
            
            CREATE INDEX IF NOT EXISTS idx_process_bytes_sent ON process_stats(bytes_sent DESC);
            CREATE INDEX IF NOT EXISTS idx_process_bytes_recv ON process_stats(bytes_recv DESC);
            CREATE INDEX IF NOT EXISTS idx_process_last_seen ON process_stats(last_seen DESC);
        )";
        
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "创建表失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        
        return true;
    }
    
    void close() {
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
    }
    
    // 插入或更新 session_flow（使用 UPSERT）
    bool upsertSessionFlow(const FlowKey& flow_key, int64_t packet_count, int64_t bytes_count,
                           double first_seen, double last_seen, const std::string& session_type) {
        const char* sql = R"(
            INSERT INTO session_flows (
                src_ip, dst_ip, src_port, dst_port, protocol,
                packet_count, bytes_count, first_seen, last_seen, session_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), ?)
            ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol) DO UPDATE SET
                packet_count = packet_count + excluded.packet_count,
                bytes_count = bytes_count + excluded.bytes_count,
                last_seen = excluded.last_seen
        )";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "准备 SQL 语句失败: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        
        // 绑定参数
        sqlite3_bind_text(stmt, 1, flow_key.src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, flow_key.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, flow_key.src_port);
        sqlite3_bind_int(stmt, 4, flow_key.dst_port);
        
        // 协议转换
        std::string protocol_str;
        if (flow_key.protocol == 6) protocol_str = "TCP";
        else if (flow_key.protocol == 17) protocol_str = "UDP";
        else protocol_str = "Other";
        sqlite3_bind_text(stmt, 5, protocol_str.c_str(), -1, SQLITE_TRANSIENT);
        
        sqlite3_bind_int64(stmt, 6, packet_count);
        sqlite3_bind_int64(stmt, 7, bytes_count);
        sqlite3_bind_double(stmt, 8, first_seen);
        sqlite3_bind_double(stmt, 9, last_seen);
        sqlite3_bind_text(stmt, 10, session_type.c_str(), -1, SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        if (rc != SQLITE_DONE) {
            std::cerr << "执行 SQL 失败: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        
        return true;
    }
    
    // 插入 DNS 会话
    bool insertDNSSession(const std::string& src_ip, const std::string& dst_ip,
                         uint16_t src_port, uint16_t dst_port, const std::string& protocol,
                         const std::string& domain, const std::string& query_type,
                         const std::string& response_ip, int payload_size,
                         double timestamp, int ttl_days = 7) {
        const char* sql = R"(
            INSERT INTO dns_sessions (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                domain, query_type, response_ip, payload_size, ttl
            ) VALUES (
                datetime(?, 'unixepoch'), ?, ?, ?, ?, ?,
                ?, ?, ?, ?, datetime(?, 'unixepoch', '+' || ? || ' days')
            )
        )";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "准备 DNS SQL 语句失败: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        
        sqlite3_bind_double(stmt, 1, timestamp);
        sqlite3_bind_text(stmt, 2, src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, src_port);
        sqlite3_bind_int(stmt, 5, dst_port);
        sqlite3_bind_text(stmt, 6, protocol.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, domain.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, query_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, response_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 10, payload_size);
        sqlite3_bind_double(stmt, 11, timestamp);
        sqlite3_bind_int(stmt, 12, ttl_days);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        if (rc != SQLITE_DONE) {
            std::cerr << "执行 DNS SQL 失败: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        
        return true;
    }
    
    // 开始事务
    bool beginTransaction() {
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "开始事务失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    }
    
    // 提交事务
    bool commit() {
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "提交事务失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    }
    
    // 回滚事务
    bool rollback() {
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "回滚事务失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    }
};

// 数据包信息（包含原始包和时间戳）
struct PacketInfo {
    pcpp::RawPacket* raw_packet;
    double timestamp;
    
    PacketInfo(pcpp::RawPacket* pkt, double ts) : raw_packet(pkt), timestamp(ts) {}
};

// DNS 信息结构
struct DNSInfo {
    std::map<std::string, std::set<std::string>> domain_to_ips;  // domain -> set(ips)
    std::vector<PacketInfo> dns_packets;  // 所有 DNS 包
};

// 提取 DNS 查询和响应信息
DNSInfo extractDNSInfo(pcpp::IFileReaderDevice* reader) {
    DNSInfo dns_info;
    pcpp::RawPacket raw_packet;
    
    // 重置文件指针到开头
    reader->close();
    reader->open();
    
    while (reader->getNextPacket(raw_packet)) {
        pcpp::Packet packet(&raw_packet);
        
        if (packet.isPacketOfType(pcpp::DNS)) {
            pcpp::DnsLayer* dns_layer = packet.getLayerOfType<pcpp::DnsLayer>();
            if (dns_layer) {
                timespec ts = raw_packet.getPacketTimeStamp();
                double timestamp = ts.tv_sec + ts.tv_nsec / 1e9;
                
                // 创建新的 RawPacket 副本
                pcpp::RawPacket* pkt_copy = new pcpp::RawPacket(raw_packet);
                dns_info.dns_packets.push_back(PacketInfo(pkt_copy, timestamp));
                
                // 处理 DNS 查询
                if (dns_layer->getDnsHeader()->queryOrResponse == 0) {  // 查询包
                    if (dns_layer->getFirstQuery() != nullptr) {
                        std::string domain = dns_layer->getFirstQuery()->getName();
                        if (!domain.empty()) {
                            // 去除末尾的点
                            if (domain.back() == '.') {
                                domain.pop_back();
                            }
                            // 转换为小写
                            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                            if (dns_info.domain_to_ips.find(domain) == dns_info.domain_to_ips.end()) {
                                dns_info.domain_to_ips[domain] = std::set<std::string>();
                            }
                        }
                    }
                }
                // 处理 DNS 响应
                else if (dns_layer->getDnsHeader()->queryOrResponse == 1) {  // 响应包
                    if (dns_layer->getFirstQuery() != nullptr) {
                        std::string domain = dns_layer->getFirstQuery()->getName();
                        if (!domain.empty()) {
                            // 去除末尾的点
                            if (domain.back() == '.') {
                                domain.pop_back();
                            }
                            // 转换为小写
                            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                            if (dns_info.domain_to_ips.find(domain) == dns_info.domain_to_ips.end()) {
                                dns_info.domain_to_ips[domain] = std::set<std::string>();
                            }
                            
                            // 只提取 A 记录（IPv4），忽略 AAAA 记录（IPv6）
                            pcpp::DnsResource* answer = dns_layer->getFirstAnswer();
                            while (answer != nullptr) {
                                if (answer->getDnsType() == pcpp::DNS_TYPE_A) {
                                    auto dataPtr = answer->getData();
                                    if (dataPtr) {
                                        auto* ipv4_data = dynamic_cast<pcpp::IPv4DnsResourceData*>(dataPtr.get());
                                        if (ipv4_data != nullptr) {
                                            std::string ip = ipv4_data->getIpAddress().toString();
                                            dns_info.domain_to_ips[domain].insert(ip);
                                        }
                                    }
                                }
                                // 忽略 AAAA 记录（IPv6）
                                answer = dns_layer->getNextAnswer(answer);
                            }
                        }
                    }
                }
            }
        }
    }
    
    return dns_info;
}

// 从数据包中提取流标识（仅处理 IPv4，忽略 IPv6）
FlowKey* getFlowKey(pcpp::Packet& packet) {
    pcpp::IPv4Layer* ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::IPv6Layer* ipv6_layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    
    // 如果只有 IPv6，忽略它
    if (ipv6_layer != nullptr && ipv4_layer == nullptr) {
        return nullptr;
    }
    
    std::string src_ip, dst_ip;
    uint8_t protocol = 0;
    
    if (ipv4_layer != nullptr) {
        src_ip = ipv4_layer->getSrcIPv4Address().toString();
        dst_ip = ipv4_layer->getDstIPv4Address().toString();
        protocol = ipv4_layer->getIPv4Header()->protocol;
    } else {
        return nullptr;
    }
    
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    
    pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    pcpp::UdpLayer* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    
    if (tcp_layer != nullptr) {
        src_port = tcp_layer->getSrcPort();
        dst_port = tcp_layer->getDstPort();
        protocol = 6;  // TCP
    } else if (udp_layer != nullptr) {
        src_port = udp_layer->getSrcPort();
        dst_port = udp_layer->getDstPort();
        protocol = 17;  // UDP
    } else {
        return nullptr;
    }
    
    return new FlowKey(src_ip, dst_ip, src_port, dst_port, protocol);
}

// 查找流对应的 DNS 查询
std::vector<std::string> findDNSForFlow(const FlowKey& flow_key, 
                                        const std::map<std::string, std::set<std::string>>& domain_to_ips,
                                        const std::map<std::string, std::vector<std::string>>& ip_to_domains) {
    std::vector<std::string> domains;
    
    // 反向查找：IP -> domain
    auto it_src = ip_to_domains.find(flow_key.src_ip);
    if (it_src != ip_to_domains.end()) {
        domains.insert(domains.end(), it_src->second.begin(), it_src->second.end());
    }
    
    auto it_dst = ip_to_domains.find(flow_key.dst_ip);
    if (it_dst != ip_to_domains.end()) {
        domains.insert(domains.end(), it_dst->second.begin(), it_dst->second.end());
    }
    
    // 去重
    std::set<std::string> unique_domains(domains.begin(), domains.end());
    domains.assign(unique_domains.begin(), unique_domains.end());
    
    return domains;
}

// 清理文件名中的非法字符
std::string sanitizeFilename(const std::string& filename) {
    std::string result = filename;
    std::string illegal_chars = "/\\:*?\"<>|";
    for (char& c : result) {
        if (illegal_chars.find(c) != std::string::npos) {
            c = '_';
        }
    }
    return result;
}

// 检查数据包列表是否全是DNS包
bool isAllDNSPackets(const std::vector<PacketInfo>& packets) {
    if (packets.empty()) {
        return false;
    }
    
    int dns_count = 0;
    for (const auto& pkt_info : packets) {
        pcpp::Packet packet(pkt_info.raw_packet);
        if (packet.isPacketOfType(pcpp::DNS)) {
            dns_count++;
        }
    }
    
    // 如果所有数据包都是DNS包，返回true
    return dns_count == static_cast<int>(packets.size());
}

// 将Raw IPv4数据包转换为Ethernet格式
// 通过手动添加Ethernet头来实现
pcpp::RawPacket* convertRawIPv4ToEthernet(pcpp::RawPacket* raw_packet) {
    if (raw_packet == nullptr) {
        return nullptr;
    }
    
    // 获取原始数据包的数据
    const uint8_t* raw_data = raw_packet->getRawData();
    size_t raw_data_len = raw_packet->getRawDataLen();
    
    if (raw_data == nullptr || raw_data_len < 20) {  // IPv4最小头部20字节
        return nullptr;
    }
    
    // 创建新的数据包，添加14字节的Ethernet头
    size_t new_len = 14 + raw_data_len;  // Ethernet头(14) + IP数据
    uint8_t* new_data = new uint8_t[new_len];
    
    // Ethernet头：目标MAC(6) + 源MAC(6) + 类型(2)
    // 使用默认MAC地址
    memset(new_data, 0, 6);  // 目标MAC
    memset(new_data + 6, 0, 6);  // 源MAC
    // 设置Ethernet类型为IPv4 (0x0800)
    new_data[12] = 0x08;
    new_data[13] = 0x00;
    
    // 复制原始IP数据
    memcpy(new_data + 14, raw_data, raw_data_len);
    
    // 创建新的RawPacket（注意：new_data会被RawPacket管理，需要设置deleteOnDestruction=true）
    pcpp::RawPacket* new_raw_packet = new pcpp::RawPacket(new_data, new_len, raw_packet->getPacketTimeStamp(), true);
    
    // 注意：new_data会被RawPacket管理，不需要手动delete
    
    return new_raw_packet;
}

// AC 自动机代码（从 domain_match.cpp 复制）
struct ACNode {
    std::map<std::string, ACNode*> children;
    ACNode* fail;
    std::vector<std::pair<std::string, int>> outputs;
    
    ACNode() : fail(nullptr) {}
    
    ~ACNode() {
        for (auto& pair : children) {
            delete pair.second;
        }
    }
};

class ACAutomaton {
private:
    ACNode* root;
    
    std::vector<std::string> reverseDomain(const std::string& domain) {
        std::vector<std::string> parts;
        std::stringstream ss(domain);
        std::string part;
        
        while (std::getline(ss, part, '.')) {
            if (!part.empty()) {
                parts.push_back(part);
            }
        }
        
        std::reverse(parts.begin(), parts.end());
        return parts;
    }
    
    void buildFail() {
        std::queue<ACNode*> q;
        root->fail = root;
        
        for (auto& pair : root->children) {
            pair.second->fail = root;
            q.push(pair.second);
        }
        
        while (!q.empty()) {
            ACNode* current = q.front();
            q.pop();
            
            for (auto& pair : current->children) {
                const std::string& key = pair.first;
                ACNode* child = pair.second;
                
                ACNode* fail = current->fail;
                while (fail != root && fail->children.find(key) == fail->children.end()) {
                    fail = fail->fail;
                }
                
                if (fail->children.find(key) != fail->children.end()) {
                    child->fail = fail->children[key];
                } else {
                    child->fail = root;
                }
                
                std::set<std::pair<std::string, int>> output_set(child->outputs.begin(), child->outputs.end());
                for (const auto& output : child->fail->outputs) {
                    output_set.insert(output);
                }
                child->outputs.assign(output_set.begin(), output_set.end());
                
                q.push(child);
            }
        }
    }
    
public:
    ACAutomaton() {
        root = new ACNode();
    }
    
    ~ACAutomaton() {
        delete root;
    }
    
    void insert(const std::string& domain, const std::string& file_name) {
        std::vector<std::string> parts = reverseDomain(domain);
        ACNode* current = root;
        
        for (const auto& part : parts) {
            if (current->children.find(part) == current->children.end()) {
                current->children[part] = new ACNode();
            }
            current = current->children[part];
        }
        
        int domain_length = static_cast<int>(parts.size());
        bool found = false;
        for (auto& output : current->outputs) {
            if (output.second == domain_length) {
                bool new_is_more_specific = (file_name.length() < output.first.length()) ||
                                           (file_name.find("category-") == std::string::npos && 
                                            output.first.find("category-") != std::string::npos);
                if (new_is_more_specific) {
                    output.first = file_name;
                }
                found = true;
                break;
            }
        }
        
        if (!found) {
            current->outputs.push_back({file_name, domain_length});
        }
    }
    
    void build() {
        buildFail();
    }
    
    std::string match(const std::string& domain) {
        std::vector<std::string> parts = reverseDomain(domain);
        ACNode* current = root;
        std::string best_match = "";
        int best_length = 0;
        
        for (size_t i = 0; i < parts.size(); i++) {
            const std::string& part = parts[i];
            
            while (current != root && current->children.find(part) == current->children.end()) {
                current = current->fail;
            }
            
            if (current->children.find(part) != current->children.end()) {
                current = current->children[part];
            }
            
            ACNode* check_node = current;
            while (check_node != root) {
                for (const auto& output : check_node->outputs) {
                    const std::string& file_name = output.first;
                    int length = output.second;
                    
                    if (length > best_length) {
                        best_length = length;
                        best_match = file_name;
                    }
                }
                check_node = check_node->fail;
            }
        }
        
        return best_match.empty() ? "unknown" : best_match;
    }
    
    std::string extractDomain(const std::string& line) {
        std::string domain;
        
        size_t attr_pos = line.find('@');
        std::string domain_part = (attr_pos != std::string::npos) ? line.substr(0, attr_pos) : line;
        
        domain_part.erase(domain_part.find_last_not_of(" \t\r\n") + 1);
        
        if (domain_part.find("domain:") == 0) {
            domain = domain_part.substr(7);
        } else if (domain_part.find("full:") == 0) {
            domain = domain_part.substr(5);
        } else if (domain_part.find("keyword:") == 0) {
            return "";
        } else if (domain_part.find("regexp:") == 0) {
            return "";
        } else {
            domain = domain_part;
        }
        
        domain.erase(0, domain.find_first_not_of(" \t\r\n"));
        domain.erase(domain.find_last_not_of(" \t\r\n") + 1);
        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
        
        if (domain.empty() || domain.find(' ') != std::string::npos || domain.find('.') == std::string::npos) {
            return "";
        }
        
        if (domain[0] == '.' || domain[domain.length() - 1] == '.' || domain.find("..") != std::string::npos) {
            return "";
        }
        
        return domain;
    }
    
    void loadFromFile(const std::string& filepath, const std::string& file_name, 
                      const std::map<std::string, std::set<std::string>>& all_domains) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            return;
        }
        
        std::string line;
        std::set<std::string> processed_domains;
        
        while (std::getline(file, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            
            if (line.empty() || line[0] == '#') {
                continue;
            }
            
            if (line.find("include:") == 0) {
                std::string include_file = line.substr(8);
                include_file.erase(0, include_file.find_first_not_of(" \t\r\n"));
                include_file.erase(include_file.find_last_not_of(" \t\r\n") + 1);
                
                if (all_domains.find(include_file) != all_domains.end()) {
                    for (const auto& domain : all_domains.at(include_file)) {
                        if (processed_domains.find(domain) == processed_domains.end()) {
                            insert(domain, file_name);
                            processed_domains.insert(domain);
                        }
                    }
                }
                continue;
            }
            
            std::string domain = extractDomain(line);
            if (!domain.empty() && processed_domains.find(domain) == processed_domains.end()) {
                insert(domain, file_name);
                processed_domains.insert(domain);
            }
        }
        
        file.close();
    }
    
    void loadFromDirectory(const std::string& dir_path) {
        if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
            return;
        }
        
        std::map<std::string, std::set<std::string>> all_domains;
        std::vector<std::pair<std::string, std::string>> file_list;
        
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (entry.is_regular_file()) {
                std::string filepath = entry.path().string();
                std::string filename = entry.path().filename().string();
                
                if (filename[0] == '.' || filename == "DS_Store") {
                    continue;
                }
                
                file_list.push_back({filepath, filename});
                
                std::ifstream file(filepath);
                if (!file.is_open()) {
                    continue;
                }
                
                std::set<std::string> domains;
                std::string line;
                
                while (std::getline(file, line)) {
                    line.erase(0, line.find_first_not_of(" \t\r\n"));
                    line.erase(line.find_last_not_of(" \t\r\n") + 1);
                    
                    if (line.empty() || line[0] == '#') {
                        continue;
                    }
                    
                    if (line.find("include:") == 0) {
                        continue;
                    }
                    
                    std::string domain = extractDomain(line);
                    if (!domain.empty()) {
                        domains.insert(domain);
                    }
                }
                
                file.close();
                all_domains[filename] = domains;
            }
        }
        
        for (const auto& file_pair : file_list) {
            loadFromFile(file_pair.first, file_pair.second, all_domains);
        }
        
        build();
    }
};

using SuffixRadixTrie = ACAutomaton;

void loadEntityMap(const std::string& json_file, ACAutomaton& trie) {
    std::ifstream file(json_file);
    if (!file.is_open()) {
        return;
    }
    
    std::string line;
    std::string current_display_name = "";
    bool in_properties = false;
    
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        size_t display_pos = line.find("\"displayName\"");
        if (display_pos != std::string::npos) {
            size_t colon_pos = line.find(':', display_pos);
            if (colon_pos != std::string::npos) {
                size_t start = line.find('"', colon_pos) + 1;
                size_t end = line.find('"', start);
                if (end != std::string::npos && start < end) {
                    current_display_name = line.substr(start, end - start);
                }
            }
        }
        
        if (line.find("\"properties\"") != std::string::npos && line.find('[') != std::string::npos) {
            in_properties = true;
            continue;
        }
        
        if (in_properties) {
            if (line[0] == '"' && line.find('.') != std::string::npos) {
                size_t start = line.find('"') + 1;
                size_t end = line.find('"', start);
                if (end != std::string::npos && start < end) {
                    std::string domain = line.substr(start, end - start);
                    if (!domain.empty() && domain.back() == ',') {
                        domain.pop_back();
                    }
                    domain.erase(0, domain.find_first_not_of(" \t\r\n"));
                    domain.erase(domain.find_last_not_of(" \t\r\n") + 1);
                    
                    if (!domain.empty() && !current_display_name.empty()) {
                        trie.insert(domain, current_display_name);
                    }
                }
            }
            
            if (line.find(']') != std::string::npos) {
                in_properties = false;
                current_display_name = "";
            }
        }
    }
    
    file.close();
    trie.build();
}

// 转义 JSON 字符串中的特殊字符
std::string escapeJsonString(const std::string& str) {
    std::ostringstream o;
    for (char c : str) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// 处理单个PCAP文件，提取DNS信息和流
void processPcapFile(const std::string& pcap_file, DNSInfo& dns_info, std::map<FlowKey, std::vector<PacketInfo>>& flows) {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcap_file);
    if (reader == nullptr || !reader->open()) {
        std::cerr << "警告: 无法读取 pcap 文件 " << pcap_file << std::endl;
        return;
    }
    
    // 提取 DNS 信息
    DNSInfo file_dns_info = extractDNSInfo(reader);
    
    // 合并DNS信息
    for (const auto& pair : file_dns_info.domain_to_ips) {
        const std::string& domain = pair.first;
        for (const std::string& ip : pair.second) {
            dns_info.domain_to_ips[domain].insert(ip);
        }
    }
    
    // 合并DNS包
    for (const auto& dns_pkt_info : file_dns_info.dns_packets) {
        dns_info.dns_packets.push_back(dns_pkt_info);
    }
    
    // 重置文件指针到开头
    reader->close();
    reader->open();
    
    // 提取流
    pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet)) {
        pcpp::Packet packet(&raw_packet);
        
        FlowKey* flow_key = getFlowKey(packet);
        if (flow_key != nullptr) {
            timespec ts = raw_packet.getPacketTimeStamp();
            double timestamp = ts.tv_sec + ts.tv_nsec / 1e9;
            
            // 创建新的 RawPacket 副本
            pcpp::RawPacket* pkt_copy = new pcpp::RawPacket(raw_packet);
            flows[*flow_key].push_back(PacketInfo(pkt_copy, timestamp));
            
            delete flow_key;
        }
    }
    
    reader->close();
    delete reader;
}

int main(int argc, char* argv[]) {
    std::string input_path = "test.pcap";
    std::string output_dir = "output";
    std::string classified_dir = output_dir + "/classified";
    std::string unknown_dir = output_dir + "/unknown";
    std::string data_dir = "domain-list-community/data";
    std::string entity_map_file = "domain-list-community/entity_map.json";
    std::string db_path = "";  // 默认数据库路径（将在output目录下创建）
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc) {
            input_path = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_dir = argv[++i];
            classified_dir = output_dir + "/classified";
            unknown_dir = output_dir + "/unknown";
        } else if (arg == "--data-dir" && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (arg == "--entity-map" && i + 1 < argc) {
            entity_map_file = argv[++i];
        } else if (arg == "--db" && i + 1 < argc) {
            db_path = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "用法: " << argv[0] << " [选项]" << std::endl;
            std::cout << "选项:" << std::endl;
            std::cout << "  --input <路径>    指定输入 pcap 文件或目录（默认: test.pcap）" << std::endl;
            std::cout << "  --output <目录>   指定输出目录（默认: output）" << std::endl;
            std::cout << "  --data-dir <目录> 指定 data 目录路径" << std::endl;
            std::cout << "  --entity-map <文件> 指定 entity_map.json 文件路径" << std::endl;
            std::cout << "  --db <文件>       指定数据库文件路径（默认: <output>/sniffer.db）" << std::endl;
            std::cout << "  --help, -h        显示帮助信息" << std::endl;
            return 0;
        }
    }
    
    // 检查输入路径是否存在
    if (!fs::exists(input_path)) {
        std::cerr << "错误: 找不到路径 " << input_path << std::endl;
        return 1;
    }
    
    // 创建输出目录
    fs::create_directories(classified_dir);
    fs::create_directories(unknown_dir);
    
    // 如果未指定数据库路径，使用 output 目录下的 sniffer.db
    if (db_path.empty()) {
        db_path = output_dir + "/sniffer.db";
    }
    
    // 加载 AC 自动机
    SuffixRadixTrie trie;
    trie.loadFromDirectory(data_dir);
    
    SuffixRadixTrie entity_trie;
    loadEntityMap(entity_map_file, entity_trie);
    
    // 收集所有PCAP文件
    std::vector<std::string> pcap_files;
    if (fs::is_directory(input_path)) {
        // 如果是目录，遍历所有PCAP文件
        for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
            if (entry.is_regular_file()) {
                std::string file_path = entry.path().string();
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".pcap" || ext == ".cap") {
                    pcap_files.push_back(file_path);
                }
            }
        }
    } else {
        // 如果是文件，直接添加
        pcap_files.push_back(input_path);
    }
    
    if (pcap_files.empty()) {
        std::cerr << "错误: 没有找到PCAP文件" << std::endl;
        return 1;
    }
    
    // 统一收集所有PCAP文件的DNS信息和流
    DNSInfo dns_info;
    std::map<FlowKey, std::vector<PacketInfo>> flows;
    
    std::cerr << "处理 " << pcap_files.size() << " 个PCAP文件..." << std::endl;
    for (size_t i = 0; i < pcap_files.size(); i++) {
        std::cerr << "  [" << (i+1) << "/" << pcap_files.size() << "] " << fs::path(pcap_files[i]).filename().string() << std::endl;
        processPcapFile(pcap_files[i], dns_info, flows);
    }
    
    // 建立 IP 到域名的反向映射
    std::map<std::string, std::vector<std::string>> ip_to_domains;
    for (const auto& pair : dns_info.domain_to_ips) {
        const std::string& domain = pair.first;
        for (const std::string& ip : pair.second) {
            ip_to_domains[ip].push_back(domain);
        }
    }
    
    // 打开数据库连接
    DatabaseManager db_manager(db_path);
    bool db_opened = db_manager.open();
    if (!db_opened) {
        std::cerr << "警告: 无法打开数据库 " << db_path << "，将跳过数据库写入" << std::endl;
    } else {
        std::cerr << "成功连接到数据库: " << db_path << std::endl;
    }
    
    // 按域名分组流
    
    // 存储每个域名组的信息
    struct DomainGroup {
        std::set<std::string> domains;  // 所有域名（去重）
        std::vector<PacketInfo> all_packets;  // 所有数据包
        std::set<pcpp::RawPacket*> packet_set;  // 用于去重
        std::string best_category;
        int flow_count;
    };
    
    std::map<std::string, DomainGroup> domain_groups;  // key: 第一个域名（小写）
    std::vector<FlowKey> unknown_flows;  // 没有域名的流
    
    std::set<FlowKey> processed_flows;
    
    for (auto& flow_pair : flows) {
        const FlowKey& flow_key = flow_pair.first;
        std::vector<PacketInfo>& flow_packets = flow_pair.second;
        
        // 跳过已处理的流（双向流只处理一次）
        if (processed_flows.find(flow_key) != processed_flows.end()) {
            continue;
        }
        
        // 检查数据包数量，少于5个直接丢弃
        if (flow_packets.size() < 5) {
            processed_flows.insert(flow_key);
            continue;
        }
        
        // 查找对应的 DNS 查询
        std::vector<std::string> domains = findDNSForFlow(flow_key, dns_info.domain_to_ips, ip_to_domains);
        
        if (!domains.empty()) {
            // 使用第一个域名作为分组key（转换为小写）
            std::string first_domain = domains[0];
            std::transform(first_domain.begin(), first_domain.end(), first_domain.begin(), ::tolower);
            
            DomainGroup& group = domain_groups[first_domain];
            
            // 添加所有域名到集合中
            for (const auto& d : domains) {
                std::string d_lower = d;
                std::transform(d_lower.begin(), d_lower.end(), d_lower.begin(), ::tolower);
                group.domains.insert(d_lower);
            }
            
            // 收集该流相关的 DNS 包
            std::set<std::string> domain_lower;
            for (const auto& d : domains) {
                std::string d_lower = d;
                std::transform(d_lower.begin(), d_lower.end(), d_lower.begin(), ::tolower);
                domain_lower.insert(d_lower);
            }
            
            // 添加流的数据包（去重）
            for (const auto& pkt_info : flow_packets) {
                if (group.packet_set.find(pkt_info.raw_packet) == group.packet_set.end()) {
                    group.all_packets.push_back(pkt_info);
                    group.packet_set.insert(pkt_info.raw_packet);
                }
            }
            
            // 添加相关的 DNS 包（去重）
            for (const auto& dns_pkt_info : dns_info.dns_packets) {
                pcpp::Packet dns_packet(dns_pkt_info.raw_packet);
                pcpp::DnsLayer* dns_layer = dns_packet.getLayerOfType<pcpp::DnsLayer>();
                if (dns_layer != nullptr && dns_layer->getFirstQuery() != nullptr) {
                    std::string domain = dns_layer->getFirstQuery()->getName();
                    if (!domain.empty()) {
                        if (domain.back() == '.') {
                            domain.pop_back();
                        }
                        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                        
                        if (domain_lower.find(domain) != domain_lower.end()) {
                            if (group.packet_set.find(dns_pkt_info.raw_packet) == group.packet_set.end()) {
                                group.all_packets.push_back(dns_pkt_info);
                                group.packet_set.insert(dns_pkt_info.raw_packet);
                            }
                        }
                    }
                }
            }
            
            group.flow_count++;
        } else {
            // 没有域名的流
            unknown_flows.push_back(flow_key);
        }
        
        processed_flows.insert(flow_key);
    }
    
    // 存储输出信息，按标签分组
    std::map<std::string, std::vector<std::string>> classified_outputs;  // 有标签且非unknown
    std::vector<std::string> unknown_outputs;  // unknown或没有域名信息的
    
    // 处理每个域名组
    for (auto& group_pair : domain_groups) {
        const std::string& first_domain = group_pair.first;
        DomainGroup& group = group_pair.second;
        
        // 检查数据包数量，少于5个直接丢弃
        if (group.all_packets.size() < 5) {
            continue;
        }
        
        // 检查是否全是DNS包，如果是则丢弃
        if (isAllDNSPackets(group.all_packets)) {
            continue;
        }
        
        // 按时间戳排序
        std::sort(group.all_packets.begin(), group.all_packets.end(),
                  [](const PacketInfo& a, const PacketInfo& b) {
                      return a.timestamp < b.timestamp;
                  });
        
        // 对域名进行匹配分类
        group.best_category = "unknown";
        for (const auto& domain : group.domains) {
            std::string result = trie.match(domain);
            
            if (result == "unknown") {
                result = entity_trie.match(domain);
            }
            
            // 如果匹配到，且比当前结果更长，则更新
            if (result != "unknown") {
                if (group.best_category == "unknown" || result.length() > group.best_category.length()) {
                    group.best_category = result;
                }
            }
        }
        
        // 确定文件名和输出路径
        std::string filename = sanitizeFilename(first_domain) + ".pcap";
        std::string final_output_path;
        
        if (group.best_category == "unknown") {
            final_output_path = unknown_dir + "/" + filename;
        } else {
            std::string category_dir = classified_dir + "/" + sanitizeFilename(group.best_category);
            fs::create_directories(category_dir);
            final_output_path = category_dir + "/" + filename;
        }
        
        // 写入 pcap 文件
        if (group.all_packets.empty()) {
            std::cerr << "警告: " << final_output_path << " 没有数据包可写入" << std::endl;
            continue;
        }
        
        // 不指定链路层类型，让writer自动检测第一个数据包的类型
        // 但只写入与第一个数据包相同链路层类型的数据包
        if (group.all_packets.empty() || group.all_packets[0].raw_packet == nullptr) {
            continue;
        }
        
        pcpp::Packet first_packet(group.all_packets[0].raw_packet);
        bool is_ethernet = first_packet.isPacketOfType(pcpp::Ethernet);
        
        // 从第一个数据包获取链路层类型
        // 如果是Raw IPv4，强制使用Ethernet格式（pcap_parser需要Ethernet格式）
        pcpp::LinkLayerType link_type = group.all_packets[0].raw_packet->getLinkLayerType();
        if (link_type == pcpp::LINKTYPE_RAW || link_type == pcpp::LINKTYPE_IPV4) {
            link_type = pcpp::LINKTYPE_ETHERNET;
        }
        pcpp::PcapFileWriterDevice writer(final_output_path, link_type);
        if (!writer.open()) {
            std::cerr << "错误: 无法写入 " << final_output_path << std::endl;
            continue;
        }
        
        int written_count = 0;
        int total_packets = group.all_packets.size();
        int null_packet_count = 0;
        int skipped_count = 0;
        for (const auto& pkt_info : group.all_packets) {
            if (pkt_info.raw_packet == nullptr) {
                null_packet_count++;
                continue;
            }
            // 只写入与第一个数据包相同链路层类型的数据包
            pcpp::Packet packet(pkt_info.raw_packet);
            bool packet_is_ethernet = packet.isPacketOfType(pcpp::Ethernet);
            
            pcpp::RawPacket* packet_to_write = pkt_info.raw_packet;
            
            // 如果数据包不是Ethernet格式，但writer需要Ethernet格式，尝试转换
            if (!packet_is_ethernet && link_type == pcpp::LINKTYPE_ETHERNET) {
                pcpp::RawPacket* converted = convertRawIPv4ToEthernet(pkt_info.raw_packet);
                if (converted != nullptr) {
                    packet_to_write = converted;
                } else {
                    skipped_count++;
                    continue;
                }
            } else if (is_ethernet != packet_is_ethernet) {
                skipped_count++;
                continue;
            }
            
            if (writer.writePacket(*packet_to_write)) {
                written_count++;
            }
            
            // 如果使用了转换后的数据包，需要删除它
            if (packet_to_write != pkt_info.raw_packet) {
                delete packet_to_write;
            }
        }
        writer.close();
        
        if (written_count == 0) {
            std::cerr << "警告: " << final_output_path << " 写入0个数据包（总数: " << total_packets;
            if (null_packet_count > 0) {
                std::cerr << ", 空指针: " << null_packet_count;
            }
            if (skipped_count > 0) {
                std::cerr << ", 跳过不同链路层类型: " << skipped_count;
            }
            std::cerr << "），删除空文件" << std::endl;
            fs::remove(final_output_path);
            continue;
        } else if (written_count < total_packets) {
            std::cerr << "警告: " << final_output_path << " 只写入了 " << written_count << "/" << total_packets << " 个数据包";
            if (null_packet_count > 0) {
                std::cerr << "（空指针: " << null_packet_count;
            }
            if (skipped_count > 0) {
                if (null_packet_count > 0) std::cerr << ", ";
                else std::cerr << "（";
                std::cerr << "跳过不同链路层类型: " << skipped_count;
            }
            if (null_packet_count > 0 || skipped_count > 0) {
                std::cerr << "）";
            }
            std::cerr << std::endl;
        }
        
        // 只有成功写入后才添加到输出列表
        if (group.best_category == "unknown") {
            unknown_outputs.push_back(filename);
        } else {
            classified_outputs[group.best_category].push_back(filename);
        }
    }
    
    // 处理没有域名的流，按IP对分组合并
    // 先过滤掉少于5个数据包的流
    std::vector<FlowKey> valid_unknown_flows;
    for (const auto& flow_key : unknown_flows) {
        if (flows[flow_key].size() >= 5) {
            valid_unknown_flows.push_back(flow_key);
        }
    }
    
    std::map<std::string, std::vector<FlowKey>> ip_pair_groups;  // key: IP对字符串
    
    for (const auto& flow_key : valid_unknown_flows) {
        std::string ip_pair = flow_key.toString();
        ip_pair_groups[ip_pair].push_back(flow_key);
    }
    
    for (const auto& ip_pair_group : ip_pair_groups) {
        const std::string& ip_pair = ip_pair_group.first;
        const std::vector<FlowKey>& flow_keys = ip_pair_group.second;
        
        // 合并所有流的数据包
        std::vector<PacketInfo> all_packets;
        std::set<pcpp::RawPacket*> packet_set;  // 用于去重
        
        for (const auto& flow_key : flow_keys) {
            for (const auto& pkt_info : flows[flow_key]) {
                if (packet_set.find(pkt_info.raw_packet) == packet_set.end()) {
                    all_packets.push_back(pkt_info);
                    packet_set.insert(pkt_info.raw_packet);
                }
            }
        }
        
        // 检查数据包数量，少于5个直接丢弃（双重检查）
        if (all_packets.size() < 5) {
            continue;
        }
        
        // 检查是否全是DNS包，如果是则丢弃
        if (isAllDNSPackets(all_packets)) {
            continue;
        }
        
        // 按时间戳排序
        std::sort(all_packets.begin(), all_packets.end(),
                  [](const PacketInfo& a, const PacketInfo& b) {
                      return a.timestamp < b.timestamp;
                  });
        
        // 确定文件名和输出路径
        std::string filename = ip_pair + ".pcap";
        std::string final_output_path = unknown_dir + "/" + filename;
        
        // 写入 pcap 文件
        if (all_packets.empty()) {
            std::cerr << "警告: " << final_output_path << " 没有数据包可写入" << std::endl;
            continue;
        }
        
        // 不指定链路层类型，让writer自动检测第一个数据包的类型
        // 但只写入与第一个数据包相同链路层类型的数据包
        if (all_packets.empty() || all_packets[0].raw_packet == nullptr) {
            continue;
        }
        
        pcpp::Packet first_packet(all_packets[0].raw_packet);
        bool is_ethernet = first_packet.isPacketOfType(pcpp::Ethernet);
        
        // 从第一个数据包获取链路层类型
        // 如果是Raw IPv4，强制使用Ethernet格式（pcap_parser需要Ethernet格式）
        pcpp::LinkLayerType link_type = all_packets[0].raw_packet->getLinkLayerType();
        if (link_type == pcpp::LINKTYPE_RAW || link_type == pcpp::LINKTYPE_IPV4) {
            link_type = pcpp::LINKTYPE_ETHERNET;
        }
        pcpp::PcapFileWriterDevice writer(final_output_path, link_type);
        if (!writer.open()) {
            std::cerr << "错误: 无法写入 " << final_output_path << std::endl;
            continue;
        }
        
        int written_count = 0;
        int total_packets = all_packets.size();
        int null_packet_count = 0;
        int skipped_count = 0;
        for (const auto& pkt_info : all_packets) {
            if (pkt_info.raw_packet == nullptr) {
                null_packet_count++;
                continue;
            }
            // 只写入与第一个数据包相同链路层类型的数据包
            pcpp::Packet packet(pkt_info.raw_packet);
            bool packet_is_ethernet = packet.isPacketOfType(pcpp::Ethernet);
            
            pcpp::RawPacket* packet_to_write = pkt_info.raw_packet;
            
            // 如果数据包不是Ethernet格式，但writer需要Ethernet格式，尝试转换
            if (!packet_is_ethernet && link_type == pcpp::LINKTYPE_ETHERNET) {
                pcpp::RawPacket* converted = convertRawIPv4ToEthernet(pkt_info.raw_packet);
                if (converted != nullptr) {
                    packet_to_write = converted;
                } else {
                    skipped_count++;
                    continue;
                }
            } else if (is_ethernet != packet_is_ethernet) {
                skipped_count++;
                continue;
            }
            
            if (writer.writePacket(*packet_to_write)) {
                written_count++;
            }
            
            // 如果使用了转换后的数据包，需要删除它
            if (packet_to_write != pkt_info.raw_packet) {
                delete packet_to_write;
            }
        }
        writer.close();
        
        if (written_count == 0) {
            std::cerr << "警告: " << final_output_path << " 写入0个数据包（总数: " << total_packets;
            if (null_packet_count > 0) {
                std::cerr << ", 空指针: " << null_packet_count;
            }
            if (skipped_count > 0) {
                std::cerr << ", 跳过不同链路层类型: " << skipped_count;
            }
            std::cerr << "），删除空文件" << std::endl;
            fs::remove(final_output_path);
            continue;
        } else if (written_count < total_packets) {
            std::cerr << "警告: " << final_output_path << " 只写入了 " << written_count << "/" << total_packets << " 个数据包";
            if (null_packet_count > 0) {
                std::cerr << "（空指针: " << null_packet_count;
            }
            if (skipped_count > 0) {
                if (null_packet_count > 0) std::cerr << ", ";
                else std::cerr << "（";
                std::cerr << "跳过不同链路层类型: " << skipped_count;
            }
            if (null_packet_count > 0 || skipped_count > 0) {
                std::cerr << "）";
            }
            std::cerr << std::endl;
        }
        
        // 只有成功写入后才添加到输出列表
        unknown_outputs.push_back(filename);
    }
    
    // 统计分类结果
    int total_flows = 0;
    int classified_flows = 0;  // 成功分类的流（非unknown）
    int unknown_flow_count = 0;
    
    // 计算分类流数量
    for (const auto& category_pair : classified_outputs) {
        classified_flows += category_pair.second.size();
        total_flows += category_pair.second.size();
    }
    unknown_flow_count = unknown_outputs.size();
    total_flows += unknown_flow_count;
    
    // 计算准确率
    double accuracy = 0.0;
    if (total_flows > 0) {
        accuracy = (static_cast<double>(classified_flows) / static_cast<double>(total_flows)) * 100.0;
    }
    
    // 输出统计信息到stderr（便于调试）
    std::cerr << std::endl << "分类统计:" << std::endl;
    std::cerr << "  - 总流数: " << total_flows << std::endl;
    std::cerr << "  - 成功分类: " << classified_flows << std::endl;
    std::cerr << "  - 未分类(unknown): " << unknown_flow_count << std::endl;
    std::cerr << "  - 准确率: " << std::fixed << std::setprecision(2) << accuracy << "%" << std::endl;
    
    // 输出统计摘要到stdout（第一行，便于脚本解析）
    std::cout << "STATS:" << total_flows << "," << classified_flows << "," << unknown_flow_count << "," << std::fixed << std::setprecision(2) << accuracy << std::endl;
    
    // 输出：先输出有标签且非unknown的（按标签分组）
    for (const auto& category_pair : classified_outputs) {
        const std::string& category = category_pair.first;
        const std::vector<std::string>& filenames = category_pair.second;
        
        for (const auto& filename : filenames) {
            std::cout << filename << "," << category << std::endl;
        }
    }
    
    // 然后输出unknown的
    for (const auto& filename : unknown_outputs) {
        std::cout << filename << ",unknown" << std::endl;
    }
    
    // 写入数据库
    if (db_opened) {
        std::cerr << std::endl << "开始写入数据库..." << std::endl;
        
        // 开始事务
        db_manager.beginTransaction();
        
        int dns_written = 0;
        int flow_written = 0;
        
        try {
            // 1. 写入 DNS 会话
            std::cerr << "  写入 DNS 会话..." << std::endl;
            for (const auto& dns_pkt_info : dns_info.dns_packets) {
                pcpp::Packet dns_packet(dns_pkt_info.raw_packet);
                pcpp::DnsLayer* dns_layer = dns_packet.getLayerOfType<pcpp::DnsLayer>();
                
                if (dns_layer && dns_layer->getFirstQuery() != nullptr) {
                    // 获取五元组信息
                    pcpp::IPv4Layer* ipv4_layer = dns_packet.getLayerOfType<pcpp::IPv4Layer>();
                    pcpp::UdpLayer* udp_layer = dns_packet.getLayerOfType<pcpp::UdpLayer>();
                    
                    if (ipv4_layer && udp_layer) {
                        std::string src_ip = ipv4_layer->getSrcIPv4Address().toString();
                        std::string dst_ip = ipv4_layer->getDstIPv4Address().toString();
                        uint16_t src_port = udp_layer->getSrcPort();
                        uint16_t dst_port = udp_layer->getDstPort();
                        
                        std::string domain = dns_layer->getFirstQuery()->getName();
                        if (!domain.empty() && domain.back() == '.') {
                            domain.pop_back();
                        }
                        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                        
                        std::string query_type;
                        switch (dns_layer->getFirstQuery()->getDnsType()) {
                            case pcpp::DNS_TYPE_A: query_type = "A"; break;
                            case pcpp::DNS_TYPE_AAAA: query_type = "AAAA"; break;
                            case pcpp::DNS_TYPE_CNAME: query_type = "CNAME"; break;
                            case pcpp::DNS_TYPE_MX: query_type = "MX"; break;
                            case pcpp::DNS_TYPE_NS: query_type = "NS"; break;
                            case pcpp::DNS_TYPE_PTR: query_type = "PTR"; break;
                            case pcpp::DNS_TYPE_SOA: query_type = "SOA"; break;
                            case pcpp::DNS_TYPE_TXT: query_type = "TXT"; break;
                            default: query_type = "Other"; break;
                        }
                        
                        std::string response_ip = "";
                        if (dns_layer->getDnsHeader()->queryOrResponse == 1) {  // 响应包
                            pcpp::DnsResource* answer = dns_layer->getFirstAnswer();
                            if (answer && answer->getDnsType() == pcpp::DNS_TYPE_A) {
                                auto dataPtr = answer->getData();
                                if (dataPtr) {
                                    auto* ipv4_data = dynamic_cast<pcpp::IPv4DnsResourceData*>(dataPtr.get());
                                    if (ipv4_data) {
                                        response_ip = ipv4_data->getIpAddress().toString();
                                    }
                                }
                            }
                        }
                        
                        int payload_size = dns_pkt_info.raw_packet->getRawDataLen();
                        
                        db_manager.insertDNSSession(
                            src_ip, dst_ip, src_port, dst_port, "UDP",
                            domain, query_type, response_ip, payload_size,
                            dns_pkt_info.timestamp
                        );
                        dns_written++;
                    }
                }
            }
            std::cerr << "    写入 " << dns_written << " 条 DNS 会话" << std::endl;
            
            // 2. 写入会话流统计
            std::cerr << "  写入会话流统计..." << std::endl;
            for (auto& flow_pair : flows) {
                const FlowKey& flow_key = flow_pair.first;
                std::vector<PacketInfo>& flow_packets = flow_pair.second;
                
                if (flow_packets.empty()) {
                    continue;
                }
                
                // 计算统计信息
                int64_t packet_count = flow_packets.size();
                int64_t bytes_count = 0;
                double first_seen = flow_packets[0].timestamp;
                double last_seen = flow_packets[0].timestamp;
                
                for (const auto& pkt_info : flow_packets) {
                    bytes_count += pkt_info.raw_packet->getRawDataLen();
                    if (pkt_info.timestamp < first_seen) first_seen = pkt_info.timestamp;
                    if (pkt_info.timestamp > last_seen) last_seen = pkt_info.timestamp;
                }
                
                // 判断会话类型
                std::string session_type = "Other";
                if (flow_key.dst_port == 53 || flow_key.src_port == 53) {
                    session_type = "DNS";
                } else if (flow_key.dst_port == 80 || flow_key.src_port == 80 ||
                          flow_key.dst_port == 8080 || flow_key.src_port == 8080) {
                    session_type = "HTTP";
                } else if (flow_key.dst_port == 443 || flow_key.src_port == 443) {
                    session_type = "HTTPS";
                } else if (flow_key.protocol == 6) {
                    session_type = "TCP";
                } else if (flow_key.protocol == 17) {
                    session_type = "UDP";
                }
                
                db_manager.upsertSessionFlow(
                    flow_key, packet_count, bytes_count,
                    first_seen, last_seen, session_type
                );
                flow_written++;
            }
            std::cerr << "    写入 " << flow_written << " 条会话流" << std::endl;
            
            // 提交事务
            db_manager.commit();
            std::cerr << "数据库写入完成！" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "数据库写入出错: " << e.what() << std::endl;
            db_manager.rollback();
        }
    }
    
    // 清理内存
    for (auto& flow_pair : flows) {
        for (auto& pkt_info : flow_pair.second) {
            delete pkt_info.raw_packet;
        }
    }
    for (auto& dns_pkt_info : dns_info.dns_packets) {
        delete dns_pkt_info.raw_packet;
    }
    
    return 0;
}

