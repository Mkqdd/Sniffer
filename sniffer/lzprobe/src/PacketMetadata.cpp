#include "PacketMetadata.h"
#include "parsers/DHCPParser.h"

std::string PacketMetadata::toString() const
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << timestamp << " ";
    
    // Output Ethernet layer if present
    if (has_ethernet) {
        oss << "HAS_ETHERNET: YES ";
        oss << "SRC_MAC: ";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(ethernet.src_mac[i]) << std::dec;
        }
        oss << " DST_MAC: ";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(ethernet.dst_mac[i]) << std::dec;
        }
        oss << " ETHERTYPE: 0x" << std::hex << ethernet.ethertype << std::dec << " ";
    }
    
    // Output WiFi layer if present
    if (has_wifi) {
        oss << "HAS_WIFI: YES ";
        oss << "WIFI_SRC_MAC: ";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(wifi.src_mac[i]) << std::dec;
        }
        oss << " WIFI_DST_MAC: ";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(wifi.dst_mac[i]) << std::dec;
        }
        oss << " WIFI_BSSID: ";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(wifi.bssid[i]) << std::dec;
        }
        oss << " WIFI_FRAME_TYPE: " << static_cast<int>(wifi.frame_type) 
            << " WIFI_FRAME_SUBTYPE: " << static_cast<int>(wifi.frame_subtype) << " ";
        if (wifi.rssi != 0) oss << "WIFI_RSSI: " << static_cast<int>(wifi.rssi) << " ";
        if (wifi.channel != 0) oss << "WIFI_CHANNEL: " << static_cast<int>(wifi.channel) << " ";
    }
    
    // Output VLAN layer if present
    if (has_vlan) {
        oss << "HAS_VLAN: YES ";
        oss << "VLAN_ID: " << vlan.vlan_id << " ";
        oss << "VLAN_PRIORITY: " << static_cast<int>(vlan.vlan_priority) << " ";
        oss << "VLAN_DEI: " << (vlan.dei_flag ? "YES" : "NO") << " ";
        oss << "INNER_ETHERTYPE: 0x" << std::hex << vlan.inner_ethertype << std::dec << " ";
    }
    
    // Output MPLS layer if present
    if (has_mpls) {
        oss << "HAS_MPLS: YES ";
        oss << "MPLS_TYPE: " << (mpls.unicast ? "UNICAST" : "MULTICAST") << " ";
        oss << "MPLS_ETHERTYPE: 0x" << std::hex << mpls.ethertype << std::dec << " ";
        oss << "MPLS_STACK_DEPTH: " << static_cast<int>(mpls.stack_depth) << " ";
        
        for (size_t i = 0; i < mpls.label_stack.size(); ++i) {
            oss << "MPLS_LABEL_" << i << ": " << mpls.label_stack[i].label << " ";
            oss << "MPLS_TC_" << i << ": " << static_cast<int>(mpls.label_stack[i].tc) << " ";
            oss << "MPLS_BOS_" << i << ": " << (mpls.label_stack[i].bos ? "YES" : "NO") << " ";
            oss << "MPLS_TTL_" << i << ": " << static_cast<int>(mpls.label_stack[i].ttl) << " ";
        }
        
        if (mpls.payload_protocol != 0) {
            oss << "MPLS_PAYLOAD_PROTOCOL: 0x" << std::hex << mpls.payload_protocol << std::dec << " ";
        }
    }
    
    // Output GRE layer if present
    if (has_gre) {
        oss << "HAS_GRE: YES ";
        oss << "GRE_VERSION: " << static_cast<int>(gre.version) << " ";
        oss << "GRE_PROTOCOL: 0x" << std::hex << gre.protocol << std::dec << " ";
        if (gre.key_bit) oss << "GRE_KEY: 0x" << std::hex << gre.key << std::dec << " ";
        if (gre.sequence_bit) oss << "GRE_SEQUENCE: " << gre.sequence << " ";
        if (gre.checksum_bit) oss << "GRE_CHECKSUM: 0x" << std::hex << gre.checksum << std::dec << " ";
        if (gre.version == 1) {
            oss << "GRE_PAYLOAD_LENGTH: " << gre.payload_length << " ";
            oss << "GRE_CALL_ID: " << gre.call_id << " ";
        }
    }
    
    // Output VXLAN layer if present
    if (has_vxlan) {
        oss << "HAS_VXLAN: YES ";
        oss << "VXLAN_FLAGS: 0x" << std::hex << static_cast<int>(vxlan.flags) << std::dec << " ";
        oss << "VXLAN_VNI: " << vxlan.vni << " ";
        oss << "VXLAN_I_BIT: " << (vxlan.i_bit ? "YES" : "NO") << " ";
    }
    
    // Output IPv4 layer if present
    if (has_ipv4) {
        oss << "HAS_IPV4: YES ";
        oss << "SRC_IP: " << ipv4.src_ip << " ";
        oss << "DST_IP: " << ipv4.dst_ip << " ";
        oss << "PROTOCOL: " << static_cast<int>(ipv4.protocol) << " ";
        oss << "TTL: " << static_cast<int>(ipv4.ttl) << " ";
        oss << "TOS: " << static_cast<int>(ipv4.tos) << " ";
        oss << "ID: " << ipv4.id << " ";
        oss << "FRAGMENT_OFFSET: " << ipv4.fragment_offset << " ";
        oss << "DF_BIT: " << (ipv4.df_bit ? "YES" : "NO") << " ";
        oss << "MF_BIT: " << (ipv4.mf_bit ? "YES" : "NO") << " ";
    }
    
    // Output IPv6 layer if present
    if (has_ipv6) {
        oss << "HAS_IPV6: YES ";
        oss << "SRC_IPV6: " << ipv6.src_ip << " ";
        oss << "DST_IPV6: " << ipv6.dst_ip << " ";
        oss << "NEXT_HEADER: " << static_cast<int>(ipv6.next_header) << " ";
        oss << "HOP_LIMIT: " << static_cast<int>(ipv6.hop_limit) << " ";
        oss << "FLOW_LABEL: " << ipv6.flow_label << " ";
        oss << "TRAFFIC_CLASS: " << static_cast<int>(ipv6.traffic_class) << " ";
        oss << "PAYLOAD_LENGTH: " << ipv6.payload_length << " ";
    }
    
    // Output DHCP layer if present
    if (has_dhcp) {
        oss << DHCPParser::formatForConsole(dhcp);
    }
    
    // Output BGP layer if present
    if (has_bgp) {
        oss << "HAS_BGP: YES ";
        oss << "BGP_TYPE: " << bgp.getMessageTypeString() << " ";
        oss << "BGP_LENGTH: " << bgp.length << " ";
        
        switch (bgp.type) {
            case BGPMetadata::OPEN:
                oss << "BGP_VERSION: " << static_cast<int>(bgp.version) << " ";
                oss << "BGP_MY_AS: " << bgp.my_as << " ";
                oss << "BGP_HOLD_TIME: " << bgp.hold_time << " ";
                oss << "BGP_IDENTIFIER: " << bgp.bgp_identifier << " ";
                break;
            case BGPMetadata::UPDATE:
                oss << bgp.getPathAttributesSummary();
                oss << bgp.getNLRI();
                break;
            case BGPMetadata::NOTIFICATION:
                oss << bgp.getErrorDescription() << " ";
                break;
            case BGPMetadata::ROUTE_REFRESH:
                oss << "BGP_AFI: " << bgp.afi << " ";
                oss << "BGP_SAFI: " << static_cast<int>(bgp.safi) << " ";
                break;
        }
    }
    
    // Output ESP layer if present
    if (has_esp) {
        oss << "HAS_ESP: YES ";
        oss << "ESP_SPI: " << esp.getSPIString() << " ";
        oss << "ESP_SEQUENCE: " << esp.getSequenceString() << " ";
        oss << "ESP_NEXT_HEADER: " << esp.getNextHeaderString() << " ";
        oss << "ESP_HEADER_LENGTH: " << esp.header_length << " ";
        oss << "ESP_PAYLOAD_LENGTH: " << esp.payload_length << " ";
        oss << "ESP_TRAILER_LENGTH: " << esp.trailer_length << " ";
        oss << "ESP_ENCRYPTED: " << (esp.is_encrypted ? "YES" : "NO") << " ";
    }
    
    // Output AH layer if present
    if (has_ah) {
        oss << "HAS_AH: YES ";
        oss << "AH_SPI: " << ah.getSPIString() << " ";
        oss << "AH_SEQUENCE: " << ah.getSequenceString() << " ";
        oss << "AH_NEXT_HEADER: " << ah.getNextHeaderString() << " ";
        oss << "AH_PAYLOAD_LENGTH: " << static_cast<int>(ah.payload_length) << " ";
        oss << "AH_HEADER_LENGTH: " << ah.header_length << " ";
        oss << "AH_ICV_LENGTH: " << ah.icv_length << " ";
        oss << "AH_ICV: " << ah.getICVString() << " ";
    }
    
    oss << "PACKET_LENGTH: " << packet_length;
    return oss.str();
}

// SSLMetadata helper methods implementation
std::string SSLMetadata::getRecordTypeString() const {
    switch (record_type) {
        case 20: return "Change Cipher Spec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "Application Data";
        default: return "Unknown (" + std::to_string(record_type) + ")";
    }
}

std::string SSLMetadata::getHandshakeTypeString() const {
    if (!is_handshake_layer) {
        return "N/A";
    }
    
    switch (handshake_data.handshake_type) {
        case 0: return "Hello Request";
        case 1: return "Client Hello";
        case 2: return "Server Hello";
        case 4: return "New Session Ticket";
        case 5: return "End of Early Data";
        case 8: return "Encrypted Extensions";
        case 11: return "Certificate";
        case 12: return "Server Key Exchange";
        case 13: return "Certificate Request";
        case 14: return "Server Hello Done";
        case 15: return "Certificate Verify";
        case 16: return "Client Key Exchange";
        case 20: return "Finished";
        default: return "Unknown (" + std::to_string(handshake_data.handshake_type) + ")";
    }
}

std::string SSLMetadata::getVersionString() const {
    uint16_t version = record_version;
    
    // For handshake messages, use handshake version if available
    if (is_handshake_layer) {
        version = handshake_data.handshake_version;
    }
    
    switch (version) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        case 0x7f0e: return "TLS 1.3 Draft 14";
        case 0x7f0f: return "TLS 1.3 Draft 15";
        case 0x7f10: return "TLS 1.3 Draft 16";
        case 0x7f11: return "TLS 1.3 Draft 17";
        case 0x7f12: return "TLS 1.3 Draft 18";
        case 0x7f13: return "TLS 1.3 Draft 19";
        case 0x7f14: return "TLS 1.3 Draft 20";
        case 0x7f15: return "TLS 1.3 Draft 21";
        case 0x7f16: return "TLS 1.3 Draft 22";
        case 0x7f17: return "TLS 1.3 Draft 23";
        case 0x7f18: return "TLS 1.3 Draft 24";
        case 0x7f19: return "TLS 1.3 Draft 25";
        case 0x7f1a: return "TLS 1.3 Draft 26";
        case 0x7f1b: return "TLS 1.3 Draft 27";
        case 0x7f1c: return "TLS 1.3 Draft 28";
        case 0xfb17: return "TLS 1.3 Facebook Draft 23";
        case 0xfb1a: return "TLS 1.3 Facebook Draft 26";
        default: return "Unknown (0x" + std::to_string(version) + ")";
    }
}

std::string SSLMetadata::getCipherSuitesString() const {
    if (!is_handshake_layer || handshake_data.cipher_suites.empty()) {
        return "None";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < handshake_data.cipher_suites.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << handshake_data.cipher_suites[i];
    }
    return oss.str();
}

std::string SSLMetadata::getExtensionsString() const {
    if (!is_handshake_layer || handshake_data.extension_types.empty()) {
        return "None";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < handshake_data.extension_types.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << handshake_data.extension_types[i];
        if (i < handshake_data.extension_names.size() && !handshake_data.extension_names[i].empty()) {
            oss << " (" << handshake_data.extension_names[i] << ")";
        }
    }
    return oss.str();
}

std::string SSLMetadata::getSupportedGroupsString() const {
    if (!is_handshake_layer || handshake_data.supported_groups.empty()) {
        return "None";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < handshake_data.supported_groups.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << handshake_data.supported_groups[i];
        if (i < handshake_data.supported_group_names.size() && !handshake_data.supported_group_names[i].empty()) {
            oss << " (" << handshake_data.supported_group_names[i] << ")";
        }
    }
    return oss.str();
}

std::string SSLMetadata::getRandomDataString() const {
    if (!is_handshake_layer || handshake_data.random_data.empty()) {
        return "None";
    }
    
    std::ostringstream oss;
    oss << "0x";
    for (size_t i = 0; i < handshake_data.random_data.size() && i < 8; ++i) { // Show first 8 bytes
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(handshake_data.random_data[i]);
    }
    if (handshake_data.random_data.size() > 8) {
        oss << "...";
    }
    return oss.str();
}

std::string SSLMetadata::getSessionIDString() const {
    if (!is_handshake_layer || handshake_data.session_id.empty()) {
        return "None";
    }
    
    std::ostringstream oss;
    oss << "0x";
    for (size_t i = 0; i < handshake_data.session_id.size() && i < 8; ++i) { // Show first 8 bytes
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(handshake_data.session_id[i]);
    }
    if (handshake_data.session_id.size() > 8) {
        oss << "...";
    }
    return oss.str();
}

// CertificateMetadata helper methods implementation
std::string CertificateMetadata::getVersionString() const {
    switch (version) {
        case 1: return "v1";
        case 2: return "v2";
        case 3: return "v3";
        default: return "unknown";
    }
}

std::string CertificateMetadata::getValidityString() const {
    std::ostringstream oss;
    if (!not_valid_before_str.empty() && !not_valid_after_str.empty()) {
        oss << "Valid from " << not_valid_before_str << " to " << not_valid_after_str;
    } else {
        oss << "Valid from " << not_valid_before << " to " << not_valid_after;
    }
    return oss.str();
}

std::string CertificateMetadata::getKeyInfoString() const {
    std::ostringstream oss;
    oss << key_type;
    if (key_length > 0) {
        oss << " (" << key_length << " bits)";
    }
    if (!exponent.empty()) {
        oss << " exp=" << exponent;
    }
    return oss.str();
}

std::string CertificateMetadata::getSANString() const {
    std::ostringstream oss;
    bool first = true;
    
    // DNS names
    for (const auto& dns : dns_names) {
        if (!first) oss << ", ";
        oss << "DNS:" << dns;
        first = false;
    }
    
    // Email addresses
    for (const auto& email : email_addresses) {
        if (!first) oss << ", ";
        oss << "EMAIL:" << email;
        first = false;
    }
    
    // IP addresses
    for (const auto& ip : ip_addresses) {
        if (!first) oss << ", ";
        oss << "IP:" << ip;
        first = false;
    }
    
    // URIs
    for (const auto& uri : uris) {
        if (!first) oss << ", ";
        oss << "URI:" << uri;
        first = false;
    }
    
    return oss.str();
}

std::string CertificateMetadata::getKeyUsageString() const {
    std::ostringstream oss;
    bool first = true;
    
    if (key_usage_digital_signature) {
        if (!first) oss << ", ";
        oss << "Digital Signature";
        first = false;
    }
    if (key_usage_non_repudiation) {
        if (!first) oss << ", ";
        oss << "Non Repudiation";
        first = false;
    }
    if (key_usage_key_encipherment) {
        if (!first) oss << ", ";
        oss << "Key Encipherment";
        first = false;
    }
    if (key_usage_data_encipherment) {
        if (!first) oss << ", ";
        oss << "Data Encipherment";
        first = false;
    }
    if (key_usage_key_agreement) {
        if (!first) oss << ", ";
        oss << "Key Agreement";
        first = false;
    }
    if (key_usage_key_cert_sign) {
        if (!first) oss << ", ";
        oss << "Key Cert Sign";
        first = false;
    }
    if (key_usage_crl_sign) {
        if (!first) oss << ", ";
        oss << "CRL Sign";
        first = false;
    }
    if (key_usage_encipher_only) {
        if (!first) oss << ", ";
        oss << "Encipher Only";
        first = false;
    }
    if (key_usage_decipher_only) {
        if (!first) oss << ", ";
        oss << "Decipher Only";
        first = false;
    }
    
    return oss.str();
}

std::string CertificateMetadata::getExtendedKeyUsageString() const {
    std::ostringstream oss;
    bool first = true;
    
    if (ext_key_usage_server_auth) {
        if (!first) oss << ", ";
        oss << "Server Authentication";
        first = false;
    }
    if (ext_key_usage_client_auth) {
        if (!first) oss << ", ";
        oss << "Client Authentication";
        first = false;
    }
    if (ext_key_usage_code_signing) {
        if (!first) oss << ", ";
        oss << "Code Signing";
        first = false;
    }
    if (ext_key_usage_email_protection) {
        if (!first) oss << ", ";
        oss << "Email Protection";
        first = false;
    }
    if (ext_key_usage_time_stamping) {
        if (!first) oss << ", ";
        oss << "Time Stamping";
        first = false;
    }
    if (ext_key_usage_ocsp_signing) {
        if (!first) oss << ", ";
        oss << "OCSP Signing";
        first = false;
    }
    
    return oss.str();
}

std::string CertificateMetadata::getIssuerString() const {
    if (!issuer.empty()) {
        return issuer;
    }
    
    std::ostringstream oss;
    bool first = true;
    
    if (!issuer_common_name.empty()) {
        oss << "CN=" << issuer_common_name;
        first = false;
    }
    if (!issuer_organization.empty()) {
        if (!first) oss << ", ";
        oss << "O=" << issuer_organization;
        first = false;
    }
    if (!issuer_organizational_unit.empty()) {
        if (!first) oss << ", ";
        oss << "OU=" << issuer_organizational_unit;
        first = false;
    }
    if (!issuer_country.empty()) {
        if (!first) oss << ", ";
        oss << "C=" << issuer_country;
        first = false;
    }
    
    return oss.str();
}

std::string CertificateMetadata::getSubjectString() const {
    if (!subject.empty()) {
        return subject;
    }
    
    std::ostringstream oss;
    bool first = true;
    
    if (!subject_common_name.empty()) {
        oss << "CN=" << subject_common_name;
        first = false;
    }
    if (!subject_organization.empty()) {
        if (!first) oss << ", ";
        oss << "O=" << subject_organization;
        first = false;
    }
    if (!subject_organizational_unit.empty()) {
        if (!first) oss << ", ";
        oss << "OU=" << subject_organizational_unit;
        first = false;
    }
    if (!subject_country.empty()) {
        if (!first) oss << ", ";
        oss << "C=" << subject_country;
        first = false;
    }
    
    return oss.str();
}

std::string CertificateMetadata::getFingerprintString() const {
    std::ostringstream oss;
    if (!fingerprint_sha256.empty()) {
        oss << "SHA256:" << fingerprint_sha256;
    }
    if (!fingerprint_sha1.empty()) {
        if (!oss.str().empty()) oss << ", ";
        oss << "SHA1:" << fingerprint_sha1;
    }
    return oss.str();
}

std::string CertificateMetadata::getExtensionsString() const {
    std::ostringstream oss;
    bool first = true;
    
    if (has_extensions) {
        if (!first) oss << ", ";
        oss << "Extensions present";
        first = false;
    }
    
    if (is_ca) {
        if (!first) oss << ", ";
        oss << "CA";
        first = false;
    }
    
    if (!dns_names.empty()) {
        if (!first) oss << ", ";
        oss << "SAN:" << dns_names.size() << " DNS names";
        first = false;
    }
    
    if (!extended_key_usage.empty()) {
        if (!first) oss << ", ";
        oss << "EKU:" << extended_key_usage.size() << " policies";
        first = false;
    }
    
    return oss.str();
}


