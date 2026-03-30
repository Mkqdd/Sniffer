#include "parsers/DNSParser.h"
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <cstring>
#include <sstream>
#include <iomanip>

bool DNSParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // DNS usually runs over UDP port 53
    if (!isDNSPacket(packet)) {
        return false;
    }
    
    auto* dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (!dnsLayer) {
        return false;
    }
    
    // Set DNS presence flag
    metadata.has_dns = true;
    metadata.dns.dns_packet_size = dnsLayer->getLayerPayloadSize();
    
    // Get DNS header
    auto* dnsHeader = dnsLayer->getDnsHeader();
    if (!dnsHeader) {
        return false;
    }
    
    // Parse DNS header fields
    parseHeader(dnsHeader, metadata);
    
    // Parse questions
    parseQuestions(dnsLayer, metadata);
    
    // Parse answer records
    parseResourceRecords(dnsLayer, pcpp::DnsResourceType::DnsAnswerType, metadata.dns.answer_records);
    
    // Parse authority records
    parseResourceRecords(dnsLayer, pcpp::DnsResourceType::DnsAuthorityType, metadata.dns.authority_records_list);
    
    // Parse additional records
    parseResourceRecords(dnsLayer, pcpp::DnsResourceType::DnsAdditionalType, metadata.dns.additional_records_list);
    
    // Calculate total records
    metadata.dns.total_records = metadata.dns.answer_records.size() + 
                                 metadata.dns.authority_records_list.size() + 
                                 metadata.dns.additional_records_list.size();
    
    return true;
}

void DNSParser::parseHeader(const pcpp::dnshdr* header, PacketMetadata& metadata) {
    // Parse header fields (convert from network byte order)
    metadata.dns.transaction_id = ntohs(header->transactionID);
    metadata.dns.questions = ntohs(header->numberOfQuestions);
    metadata.dns.answers = ntohs(header->numberOfAnswers);
    metadata.dns.authority_records = ntohs(header->numberOfAuthority);
    metadata.dns.additional_records = ntohs(header->numberOfAdditional);
    
    // Parse flags field
    metadata.dns.qr = header->queryOrResponse != 0;          // Query/Response flag
    metadata.dns.opcode = header->opcode;                   // Operation code (4 bits)
    metadata.dns.aa = header->authoritativeAnswer != 0;     // Authoritative Answer
    metadata.dns.tc = header->truncation != 0;              // Truncation
    metadata.dns.rd = header->recursionDesired != 0;        // Recursion Desired
    metadata.dns.ra = header->recursionAvailable != 0;      // Recursion Available
    metadata.dns.z = header->zero;                          // Reserved (3 bits)
    metadata.dns.rcode = header->responseCode;              // Response code (4 bits)
    
    // Set convenience flags and strings
    metadata.dns.is_query = !metadata.dns.qr;
    metadata.dns.is_response = metadata.dns.qr;
    metadata.dns.message_type = metadata.dns.qr ? "RESPONSE" : "QUERY";
    metadata.dns.opcode_str = DNSParser::getOpcodeString(metadata.dns);
    metadata.dns.rcode_str = DNSParser::getRcodeString(metadata.dns);
}

void DNSParser::parseQuestions(pcpp::DnsLayer* dnsLayer, PacketMetadata& metadata) {
    // Parse first question for simplicity
    auto* query = dnsLayer->getFirstQuery();
    if (query) {
        metadata.dns.qname = query->getName();
        metadata.dns.qtype = static_cast<uint16_t>(query->getDnsType());
        metadata.dns.qclass = static_cast<uint16_t>(query->getDnsClass());
        metadata.dns.qtype_str = DNSParser::getQtypeString(metadata.dns);
        metadata.dns.qclass_str = DNSParser::getQclassString(metadata.dns);
    }
}

void DNSParser::parseResourceRecords(pcpp::DnsLayer* dnsLayer, pcpp::DnsResourceType sectionType, 
                                   std::vector<DNSMetadata::DNSResourceRecord>& records) {
    pcpp::DnsResource* resource = nullptr;
    
    switch (sectionType) {
        case pcpp::DnsResourceType::DnsAnswerType:
            resource = dnsLayer->getFirstAnswer();
            break;
        case pcpp::DnsResourceType::DnsAuthorityType:
            resource = dnsLayer->getFirstAuthority();
            break;
        case pcpp::DnsResourceType::DnsAdditionalType:
            resource = dnsLayer->getFirstAdditionalRecord();
            break;
        default:
            return;
    }
    
    while (resource) {
        DNSMetadata::DNSResourceRecord record;
        
        // Parse basic fields
        record.name = resource->getName();
        record.type = static_cast<uint16_t>(resource->getDnsType());
        record.rr_class = static_cast<uint16_t>(resource->getDnsClass());
        record.ttl = resource->getTTL();
        record.rdlength = static_cast<uint16_t>(resource->getDataLength());
        record.type_str = DNSParser::getTypeString(record.type);
        
        // Parse resource data
        parseResourceData(resource, record);
        
        records.push_back(record);
        
        // Get next resource record
        switch (sectionType) {
            case pcpp::DnsResourceType::DnsAnswerType:
                resource = dnsLayer->getNextAnswer(resource);
                break;
            case pcpp::DnsResourceType::DnsAuthorityType:
                resource = dnsLayer->getNextAuthority(resource);
                break;
            case pcpp::DnsResourceType::DnsAdditionalType:
                resource = dnsLayer->getNextAdditionalRecord(resource);
                break;
            default:
                resource = nullptr;
        }
    }
}

void DNSParser::parseResourceData(pcpp::DnsResource* resource, DNSMetadata::DNSResourceRecord& record) {
    auto dataPtr = resource->getData();
    if (!dataPtr) {
        record.rdata = "NO_DATA";
        return;
    }
    
    switch (resource->getDnsType()) {
        case pcpp::DNS_TYPE_A: {
            auto* aData = dynamic_cast<pcpp::IPv4DnsResourceData*>(dataPtr.get());
            if (aData) {
                record.rdata = aData->getIpAddress().toString();
            } else {
                record.rdata = "INVALID_A_DATA";
            }
            break;
        }
        
        case pcpp::DNS_TYPE_AAAA: {
            auto* aaaaData = dynamic_cast<pcpp::IPv6DnsResourceData*>(dataPtr.get());
            if (aaaaData) {
                record.rdata = aaaaData->getIpAddress().toString();
            } else {
                record.rdata = "INVALID_AAAA_DATA";
            }
            break;
        }
        
        case pcpp::DNS_TYPE_NS:
        case pcpp::DNS_TYPE_CNAME:
        case pcpp::DNS_TYPE_PTR: {
            auto* nameData = dynamic_cast<pcpp::StringDnsResourceData*>(dataPtr.get());
            if (nameData) {
                record.rdata = nameData->toString();
            } else {
                record.rdata = "INVALID_NAME_DATA";
            }
            break;
        }
        
        case pcpp::DNS_TYPE_MX: {
            auto* mxData = dynamic_cast<pcpp::MxDnsResourceData*>(dataPtr.get());
            if (mxData) {
                auto mxDataStruct = mxData->getMxData();
                record.rdata = std::to_string(mxDataStruct.preference) + " " + mxDataStruct.mailExchange;
            } else {
                record.rdata = "INVALID_MX_DATA";
            }
            break;
        }
        
        case pcpp::DNS_TYPE_TXT: {
            auto* txtData = dynamic_cast<pcpp::GenericDnsResourceData*>(dataPtr.get());
            if (txtData) {
                record.rdata = txtData->toString();
            } else {
                record.rdata = "INVALID_TXT_DATA";
            }
            break;
        }
        
        case pcpp::DNS_TYPE_SOA: {
            auto* soaData = dynamic_cast<pcpp::GenericDnsResourceData*>(dataPtr.get());
            if (soaData) {
                record.rdata = soaData->toString();
            } else {
                record.rdata = "INVALID_SOA_DATA";
            }
            break;
        }
        
        default: {
            // For unsupported types, try to get raw data
            auto* genericData = dynamic_cast<pcpp::GenericDnsResourceData*>(dataPtr.get());
            if (genericData) {
                record.rdata = genericData->toString();
            } else {
                record.rdata = "UNSUPPORTED_TYPE";
            }
            break;
        }
    }
}

bool DNSParser::isDNSPacket(pcpp::Packet& packet) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Check if it's DNS port (53) or common alternative ports
    uint16_t srcPort = udpLayer->getSrcPort();
    uint16_t dstPort = udpLayer->getDstPort();
    
    if (srcPort == 53 || dstPort == 53 ||      // Standard DNS
        srcPort == 5353 || dstPort == 5353 ||  // mDNS
        srcPort == 5355 || dstPort == 5355) {  // LLMNR
        return true;
    }
    
    // For non-standard ports, check if packet contains DNS layer
    auto* dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    return dnsLayer != nullptr;
}

std::string DNSParser::getOpcodeString(const DNSMetadata& dns_meta) {
    switch (dns_meta.opcode) {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        case 4: return "NOTIFY";
        case 5: return "UPDATE";
        default: return "UNKNOWN(" + std::to_string(dns_meta.opcode) + ")";
    }
}

std::string DNSParser::getRcodeString(const DNSMetadata& dns_meta) {
    switch (dns_meta.rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMPL";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10: return "NOTZONE";
        default: return "UNKNOWN(" + std::to_string(dns_meta.rcode) + ")";
    }
}

std::string DNSParser::getQtypeString(const DNSMetadata& dns_meta) {
    return getTypeString(dns_meta.qtype);
}

std::string DNSParser::getQclassString(const DNSMetadata& dns_meta) {
    switch (dns_meta.qclass) {
        case 1: return "IN";
        case 2: return "CS";
        case 3: return "CH";
        case 4: return "HS";
        case 255: return "ANY";
        default: return "UNKNOWN(" + std::to_string(dns_meta.qclass) + ")";
    }
}

std::string DNSParser::getTypeString(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 39: return "DNAME";
        case 41: return "OPT";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        case 51: return "NSEC3PARAM";
        case 255: return "ANY";
        default: return "TYPE" + std::to_string(type);
    }
}

std::string DNSParser::getFlagsString(const DNSMetadata& dns_meta) {
    std::string flags_str;
    if (dns_meta.qr) flags_str += "QR ";
    if (dns_meta.aa) flags_str += "AA ";
    if (dns_meta.tc) flags_str += "TC ";
    if (dns_meta.rd) flags_str += "RD ";
    if (dns_meta.ra) flags_str += "RA ";
    if (flags_str.empty()) {
        return "NONE";
    }
    // Remove trailing space
    if (!flags_str.empty() && flags_str.back() == ' ') {
        flags_str.pop_back();
    }
    return flags_str;
}
