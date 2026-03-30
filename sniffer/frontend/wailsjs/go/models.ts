export namespace config {
	
	export class Config {
	    RawMax: number;
	    DNSMax: number;
	    HTTPMax: number;
	    ICMPMax: number;
	    PcapRotate: number;
	    PcapSize: string;
	    PcapCompress: number;
	    DBVacuumDay: number;
	    DBVacuumInterval: string;
	    DataDir: string;
	    PcapDir: string;
	    DBPath: string;
	    SnapshotLen: number;
	    Promiscuous: boolean;
	    Timeout: string;
	    BufferSize: string;
	    SSLBlacklistDir: string;
	    MaltrailEnabled: boolean;
	    MaltrailUDPListen: string;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.RawMax = source["RawMax"];
	        this.DNSMax = source["DNSMax"];
	        this.HTTPMax = source["HTTPMax"];
	        this.ICMPMax = source["ICMPMax"];
	        this.PcapRotate = source["PcapRotate"];
	        this.PcapSize = source["PcapSize"];
	        this.PcapCompress = source["PcapCompress"];
	        this.DBVacuumDay = source["DBVacuumDay"];
	        this.DBVacuumInterval = source["DBVacuumInterval"];
	        this.DataDir = source["DataDir"];
	        this.PcapDir = source["PcapDir"];
	        this.DBPath = source["DBPath"];
	        this.SnapshotLen = source["SnapshotLen"];
	        this.Promiscuous = source["Promiscuous"];
	        this.Timeout = source["Timeout"];
	        this.BufferSize = source["BufferSize"];
	        this.SSLBlacklistDir = source["SSLBlacklistDir"];
	        this.MaltrailEnabled = source["MaltrailEnabled"];
	        this.MaltrailUDPListen = source["MaltrailUDPListen"];
	    }
	}
	export class Limits {
	    raw_max: number;
	    dns_max: number;
	    http_max: number;
	    icmp_max: number;
	
	    static createFrom(source: any = {}) {
	        return new Limits(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.raw_max = source["raw_max"];
	        this.dns_max = source["dns_max"];
	        this.http_max = source["http_max"];
	        this.icmp_max = source["icmp_max"];
	    }
	}

}

export namespace model {
	
	export class AlertLogQuery {
	    rule_id?: number;
	    rule_type?: string;
	    alert_level?: string;
	    acknowledged?: boolean;
	    start_time?: string;
	    end_time?: string;
	    limit: number;
	    offset: number;
	    sort_by: string;
	    sort_order: string;
	
	    static createFrom(source: any = {}) {
	        return new AlertLogQuery(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rule_id = source["rule_id"];
	        this.rule_type = source["rule_type"];
	        this.alert_level = source["alert_level"];
	        this.acknowledged = source["acknowledged"];
	        this.start_time = source["start_time"];
	        this.end_time = source["end_time"];
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	        this.sort_by = source["sort_by"];
	        this.sort_order = source["sort_order"];
	    }
	}
	export class AlertRule {
	    id: number;
	    name: string;
	    rule_type: string;
	    enabled: boolean;
	    condition_field: string;
	    condition_operator: string;
	    condition_value: string;
	    alert_level: string;
	    description: string;
	    created_at: string;
	    updated_at: string;
	
	    static createFrom(source: any = {}) {
	        return new AlertRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.rule_type = source["rule_type"];
	        this.enabled = source["enabled"];
	        this.condition_field = source["condition_field"];
	        this.condition_operator = source["condition_operator"];
	        this.condition_value = source["condition_value"];
	        this.alert_level = source["alert_level"];
	        this.description = source["description"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class AlertRuleQuery {
	    rule_type?: string;
	    enabled?: boolean;
	    limit: number;
	    offset: number;
	
	    static createFrom(source: any = {}) {
	        return new AlertRuleQuery(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rule_type = source["rule_type"];
	        this.enabled = source["enabled"];
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	    }
	}
	export class TrafficPoint {
	    timestamp: number;
	    packets: number;
	    bytes: number;
	    pps: number;
	    bps: number;
	
	    static createFrom(source: any = {}) {
	        return new TrafficPoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	        this.pps = source["pps"];
	        this.bps = source["bps"];
	    }
	}
	export class DomainStat {
	    domain: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new DomainStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.count = source["count"];
	    }
	}
	export class PortStat {
	    port: number;
	    count: number;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new PortStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.count = source["count"];
	        this.bytes = source["bytes"];
	    }
	}
	export class IPStat {
	    ip: string;
	    count: number;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new IPStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.count = source["count"];
	        this.bytes = source["bytes"];
	    }
	}
	export class DashboardStats {
	    total_packets: number;
	    total_bytes: number;
	    avg_packet_size: number;
	    capture_time: number;
	    tcp_count: number;
	    udp_count: number;
	    icmp_count: number;
	    other_count: number;
	    dns_sessions: number;
	    http_sessions: number;
	    icmp_sessions: number;
	    session_flows_count: number;
	    top_src_ips: IPStat[];
	    top_dst_ips: IPStat[];
	    top_ports: PortStat[];
	    top_domains: DomainStat[];
	    traffic_trend: TrafficPoint[];
	    storage_size: number;
	    pcap_file_count: number;
	
	    static createFrom(source: any = {}) {
	        return new DashboardStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total_packets = source["total_packets"];
	        this.total_bytes = source["total_bytes"];
	        this.avg_packet_size = source["avg_packet_size"];
	        this.capture_time = source["capture_time"];
	        this.tcp_count = source["tcp_count"];
	        this.udp_count = source["udp_count"];
	        this.icmp_count = source["icmp_count"];
	        this.other_count = source["other_count"];
	        this.dns_sessions = source["dns_sessions"];
	        this.http_sessions = source["http_sessions"];
	        this.icmp_sessions = source["icmp_sessions"];
	        this.session_flows_count = source["session_flows_count"];
	        this.top_src_ips = this.convertValues(source["top_src_ips"], IPStat);
	        this.top_dst_ips = this.convertValues(source["top_dst_ips"], IPStat);
	        this.top_ports = this.convertValues(source["top_ports"], PortStat);
	        this.top_domains = this.convertValues(source["top_domains"], DomainStat);
	        this.traffic_trend = this.convertValues(source["traffic_trend"], TrafficPoint);
	        this.storage_size = source["storage_size"];
	        this.pcap_file_count = source["pcap_file_count"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class FiveTuple {
	    src_ip: string;
	    dst_ip: string;
	    src_port: number;
	    dst_port: number;
	    protocol: string;
	
	    static createFrom(source: any = {}) {
	        return new FiveTuple(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.src_port = source["src_port"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	    }
	}
	
	export class MaltrailEvent {
	    id: number;
	    timestamp: string;
	    sensor_name: string;
	    src_ip: string;
	    src_port: string;
	    dst_ip: string;
	    dst_port: string;
	    protocol: string;
	    trail_type: string;
	    trail: string;
	    info: string;
	    reference: string;
	    created_at: string;
	
	    static createFrom(source: any = {}) {
	        return new MaltrailEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.sensor_name = source["sensor_name"];
	        this.src_ip = source["src_ip"];
	        this.src_port = source["src_port"];
	        this.dst_ip = source["dst_ip"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.trail_type = source["trail_type"];
	        this.trail = source["trail"];
	        this.info = source["info"];
	        this.reference = source["reference"];
	        this.created_at = source["created_at"];
	    }
	}
	export class MaltrailEventList {
	    data: MaltrailEvent[];
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new MaltrailEventList(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = this.convertValues(source["data"], MaltrailEvent);
	        this.total = source["total"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Metrics {
	    timestamp: string;
	    interface: string;
	    is_capturing: boolean;
	    is_paused: boolean;
	    packets_total: number;
	    packets_dropped: number;
	    bytes_total: number;
	    packets_per_sec: number;
	    bytes_per_sec: number;
	    raw_count: number;
	    dns_count: number;
	    http_count: number;
	    icmp_count: number;
	
	    static createFrom(source: any = {}) {
	        return new Metrics(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.interface = source["interface"];
	        this.is_capturing = source["is_capturing"];
	        this.is_paused = source["is_paused"];
	        this.packets_total = source["packets_total"];
	        this.packets_dropped = source["packets_dropped"];
	        this.bytes_total = source["bytes_total"];
	        this.packets_per_sec = source["packets_per_sec"];
	        this.bytes_per_sec = source["bytes_per_sec"];
	        this.raw_count = source["raw_count"];
	        this.dns_count = source["dns_count"];
	        this.http_count = source["http_count"];
	        this.icmp_count = source["icmp_count"];
	    }
	}
	export class NetworkInterface {
	    name: string;
	    description: string;
	    addresses: string[];
	    is_physical: boolean;
	    is_loopback: boolean;
	    is_up: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NetworkInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.addresses = source["addresses"];
	        this.is_physical = source["is_physical"];
	        this.is_loopback = source["is_loopback"];
	        this.is_up = source["is_up"];
	    }
	}
	export class Packet {
	    id: number;
	    timestamp: string;
	    length: number;
	    capture_len: number;
	    src_ip: string;
	    dst_ip: string;
	    src_port: number;
	    dst_port: number;
	    protocol: string;
	    layer_info: string;
	    process_pid?: number;
	    process_name?: string;
	    process_exe?: string;
	
	    static createFrom(source: any = {}) {
	        return new Packet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.length = source["length"];
	        this.capture_len = source["capture_len"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.src_port = source["src_port"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.layer_info = source["layer_info"];
	        this.process_pid = source["process_pid"];
	        this.process_name = source["process_name"];
	        this.process_exe = source["process_exe"];
	    }
	}
	
	export class QueryOptions {
	    table: string;
	    limit: number;
	    offset: number;
	    sort_by: string;
	    sort_order: string;
	    search_text: string;
	    search_type: string;
	
	    static createFrom(source: any = {}) {
	        return new QueryOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.table = source["table"];
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	        this.sort_by = source["sort_by"];
	        this.sort_order = source["sort_order"];
	        this.search_text = source["search_text"];
	        this.search_type = source["search_type"];
	    }
	}
	export class Session {
	    id: number;
	    timestamp: string;
	    five_tuple: FiveTuple;
	    type: string;
	    domain?: string;
	    query_type?: string;
	    response_ip?: string;
	    method?: string;
	    path?: string;
	    status_code?: number;
	    host?: string;
	    user_agent?: string;
	    content_type?: string;
	    post_data?: string;
	    icmp_type?: number;
	    icmp_code?: number;
	    icmp_seq?: number;
	    payload_size: number;
	    ttl: string;
	    process_pid?: number;
	    process_name?: string;
	    process_exe?: string;
	
	    static createFrom(source: any = {}) {
	        return new Session(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.five_tuple = this.convertValues(source["five_tuple"], FiveTuple);
	        this.type = source["type"];
	        this.domain = source["domain"];
	        this.query_type = source["query_type"];
	        this.response_ip = source["response_ip"];
	        this.method = source["method"];
	        this.path = source["path"];
	        this.status_code = source["status_code"];
	        this.host = source["host"];
	        this.user_agent = source["user_agent"];
	        this.content_type = source["content_type"];
	        this.post_data = source["post_data"];
	        this.icmp_type = source["icmp_type"];
	        this.icmp_code = source["icmp_code"];
	        this.icmp_seq = source["icmp_seq"];
	        this.payload_size = source["payload_size"];
	        this.ttl = source["ttl"];
	        this.process_pid = source["process_pid"];
	        this.process_name = source["process_name"];
	        this.process_exe = source["process_exe"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class QueryResult {
	    total: number;
	    data: Session[];
	
	    static createFrom(source: any = {}) {
	        return new QueryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.data = this.convertValues(source["data"], Session);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class SessionFlow {
	    id: number;
	    src_ip: string;
	    dst_ip: string;
	    src_port: number;
	    dst_port: number;
	    protocol: string;
	    packet_count: number;
	    bytes_count: number;
	    first_seen: string;
	    last_seen: string;
	    duration: number;
	    session_type: string;
	    process_pid?: number;
	    process_name?: string;
	    process_exe?: string;
	
	    static createFrom(source: any = {}) {
	        return new SessionFlow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.src_port = source["src_port"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.packet_count = source["packet_count"];
	        this.bytes_count = source["bytes_count"];
	        this.first_seen = source["first_seen"];
	        this.last_seen = source["last_seen"];
	        this.duration = source["duration"];
	        this.session_type = source["session_type"];
	        this.process_pid = source["process_pid"];
	        this.process_name = source["process_name"];
	        this.process_exe = source["process_exe"];
	    }
	}
	export class SessionFlowQuery {
	    limit: number;
	    offset: number;
	    sort_by: string;
	    sort_order: string;
	
	    static createFrom(source: any = {}) {
	        return new SessionFlowQuery(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	        this.sort_by = source["sort_by"];
	        this.sort_order = source["sort_order"];
	    }
	}
	export class SessionFlowResult {
	    total: number;
	    data: SessionFlow[];
	
	    static createFrom(source: any = {}) {
	        return new SessionFlowResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.data = this.convertValues(source["data"], SessionFlow);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace process {
	
	export class ProcessStats {
	    pid: number;
	    name: string;
	    exe: string;
	    username: string;
	    packets_sent: number;
	    packets_recv: number;
	    bytes_sent: number;
	    bytes_recv: number;
	    connections: number;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	
	    static createFrom(source: any = {}) {
	        return new ProcessStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.name = source["name"];
	        this.exe = source["exe"];
	        this.username = source["username"];
	        this.packets_sent = source["packets_sent"];
	        this.packets_recv = source["packets_recv"];
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_recv = source["bytes_recv"];
	        this.connections = source["connections"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace server {
	
	export class ImportMaltrailTrailsResult {
	    imported: number;
	    deleted: number;
	
	    static createFrom(source: any = {}) {
	        return new ImportMaltrailTrailsResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.imported = source["imported"];
	        this.deleted = source["deleted"];
	    }
	}
	export class IntelSyncResult {
	    counts: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new IntelSyncResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.counts = source["counts"];
	    }
	}
	export class ProcessStatsResult {
	    data: process.ProcessStats[];
	    total: number;
	    page: number;
	    page_size: number;
	
	    static createFrom(source: any = {}) {
	        return new ProcessStatsResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = this.convertValues(source["data"], process.ProcessStats);
	        this.total = source["total"];
	        this.page = source["page"];
	        this.page_size = source["page_size"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace store {
	
	export class IntelCategory {
	    id: number;
	    name: string;
	    enabled: boolean;
	    description: string;
	    updated_at: string;
	
	    static createFrom(source: any = {}) {
	        return new IntelCategory(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.description = source["description"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class StoreStats {
	    RawCount: number;
	    DNSCount: number;
	    HTTPCount: number;
	    ICMPCount: number;
	    TotalSize: number;
	    // Go type: time
	    OldestPacket: any;
	    // Go type: time
	    NewestPacket: any;
	    PcapFileCount: number;
	
	    static createFrom(source: any = {}) {
	        return new StoreStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.RawCount = source["RawCount"];
	        this.DNSCount = source["DNSCount"];
	        this.HTTPCount = source["HTTPCount"];
	        this.ICMPCount = source["ICMPCount"];
	        this.TotalSize = source["TotalSize"];
	        this.OldestPacket = this.convertValues(source["OldestPacket"], null);
	        this.NewestPacket = this.convertValues(source["NewestPacket"], null);
	        this.PcapFileCount = source["PcapFileCount"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

