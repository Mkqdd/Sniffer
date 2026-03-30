#include "parsers/BGPParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/BgpLayer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

bool BGPParser::isBGPPacket(const pcpp::Packet& packet) {
    // Check if packet has BGP layer
    auto* bgpLayer = packet.getLayerOfType<pcpp::BgpLayer>();
    if (bgpLayer) {
        return true;
    }
    
    // Fallback: Check if packet has TCP layer with BGP port (179)
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }
    
    // Check if source or destination port is BGP port (179)
    uint16_t srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
    uint16_t dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);
    
    return (srcPort == 179 || dstPort == 179);
}

bool BGPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First check if this is a potential BGP packet
    if (!isBGPPacket(packet)) {
        return false;
    }
    
    // Get BGP layer
    auto* bgpLayer = packet.getLayerOfType<pcpp::BgpLayer>();
    if (!bgpLayer) {
        return false;
    }
    
    // Set BGP presence flag
    metadata.has_bgp = true;
    metadata.protocol = "TCP";
    metadata.application_protocol = "bgp";
    
    // Parse BGP header using PcapPlusPlus BGP layer
    metadata.bgp.marker = bytesToHexString(bgpLayer->getData(), 16);
    metadata.bgp.length = bgpLayer->getHeaderLen();
    metadata.bgp.type = static_cast<uint8_t>(bgpLayer->getBgpMessageType());
    metadata.bgp.type_str = metadata.bgp.getMessageTypeString();
    
    // Parse BGP message body based on type
    switch (bgpLayer->getBgpMessageType()) {
        case pcpp::BgpLayer::Open:
            parseOpenMessage(bgpLayer, metadata.bgp);
            break;
        case pcpp::BgpLayer::Update:
            parseUpdateMessage(bgpLayer, metadata.bgp);
            break;
        case pcpp::BgpLayer::Notification:
            parseNotificationMessage(bgpLayer, metadata.bgp);
            break;
        case pcpp::BgpLayer::RouteRefresh:
            parseRouteRefreshMessage(bgpLayer, metadata.bgp);
            break;
        case pcpp::BgpLayer::Keepalive:
            // KEEPALIVE has no additional data
            break;
        default:
            // Unknown message type
            break;
    }
    
    return true;
}

void BGPParser::parseOpenMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata) {
    // Cast to BgpOpenMessageLayer to access OPEN-specific methods
    auto* openLayer = dynamic_cast<const pcpp::BgpOpenMessageLayer*>(bgpLayer);
    if (!openLayer) return;
    
    // Get OPEN message header
    auto* openMsg = openLayer->getOpenMsgHeader();
    if (!openMsg) return;
    
    // Parse OPEN message fields
    metadata.version = openMsg->version;
    metadata.my_as = ntohs(openMsg->myAutonomousSystem);
    metadata.hold_time = ntohs(openMsg->holdTime);
    
    // BGP Identifier (Router ID)
    pcpp::IPv4Address bgpId = openLayer->getBgpId();
    metadata.bgp_identifier = bgpId.toString();
    
    // Optional parameters - for now, just note that we have them
    // In a full implementation, you would parse the optional parameters from the raw data
    metadata.optional_parameters.push_back("OPTIONAL_PARAMETERS_PRESENT");
}

void BGPParser::parseUpdateMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata) {
    // Cast to BgpUpdateMessageLayer to access UPDATE-specific methods
    auto* updateLayer = dynamic_cast<const pcpp::BgpUpdateMessageLayer*>(bgpLayer);
    if (!updateLayer) return;
    
    // For now, we'll use a simplified approach since the full UPDATE parsing is complex
    // In a real implementation, you would parse withdrawn routes, path attributes, and NLRI
    
    // Add placeholder for path attributes and NLRI
    metadata.path_attributes.push_back("UPDATE_MESSAGE_PARSED");
    metadata.nlri.push_back("UPDATE_MESSAGE_PARSED");
}

void BGPParser::parseNotificationMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata) {
    // Cast to BgpNotificationMessageLayer to access NOTIFICATION-specific methods
    auto* notificationLayer = dynamic_cast<const pcpp::BgpNotificationMessageLayer*>(bgpLayer);
    if (!notificationLayer) return;
    
    // For now, we'll use a simplified approach
    // In a real implementation, you would parse error code, subcode, and error data
    
    metadata.error_code = 0; // Placeholder
    metadata.error_subcode = 0; // Placeholder
    metadata.error_data = "NOTIFICATION_MESSAGE_PARSED";
}

void BGPParser::parseRouteRefreshMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata) {
    // Cast to BgpRouteRefreshMessageLayer to access ROUTE-REFRESH-specific methods
    auto* routeRefreshLayer = dynamic_cast<const pcpp::BgpRouteRefreshMessageLayer*>(bgpLayer);
    if (!routeRefreshLayer) return;
    
    // For now, we'll use a simplified approach
    // In a real implementation, you would parse AFI, SAFI, and reserved fields
    
    metadata.afi = 0; // Placeholder
    metadata.safi = 0; // Placeholder
    metadata.reserved = 0; // Placeholder
}

void BGPParser::parsePathAttributes(const std::vector<pcpp::BgpOpenMessageLayer::optional_parameter>& pathAttributes, BGPMetadata& metadata) {
    // For now, just note that we have path attributes
    // In a full implementation, you would parse the actual path attributes
    metadata.path_attributes.push_back("PATH_ATTRIBUTES_PRESENT (Count: " + std::to_string(pathAttributes.size()) + ")");
}

void BGPParser::parseNLRI(const std::vector<std::string>& nlri, BGPMetadata& metadata) {
    for (const auto& route : nlri) {
        metadata.nlri.push_back(route);
    }
}

std::string BGPParser::bytesToHexString(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i++) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string BGPParser::ipBytesToString(const uint8_t* data, size_t length) {
    if (length == 4) {
        // IPv4
        struct in_addr addr;
        memcpy(&addr.s_addr, data, 4);
        return inet_ntoa(addr);
    } else if (length == 16) {
        // IPv6
        char ip6str[INET6_ADDRSTRLEN];
        struct in6_addr addr6;
        memcpy(&addr6, data, 16);
        inet_ntop(AF_INET6, &addr6, ip6str, INET6_ADDRSTRLEN);
        return std::string(ip6str);
    }
    return bytesToHexString(data, length);
}

std::string BGPParser::formatForConsole(const BGPMetadata& bgp) {
    std::ostringstream oss;
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
    
    return oss.str();
}

