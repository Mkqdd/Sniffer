#include "parsers/VLANParser.h"
#include <pcapplusplus/VlanLayer.h>
#include <netinet/in.h>

bool VLANParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* vlanLayer = packet.getLayerOfType<pcpp::VlanLayer>();
    if (!vlanLayer) {
        return false;
    }

    // Set VLAN presence flag and extract VLAN information
    metadata.has_vlan = true;
    
    // Get VLAN header and extract fields
    auto* vlanHeader = vlanLayer->getVlanHeader();
    uint16_t vlanTag = ntohs(vlanHeader->vlan);
    
    metadata.vlan.vlan_id = vlanTag & 0x0FFF;  // 12-bit VLAN ID
    metadata.vlan.vlan_priority = (vlanTag >> 13) & 0x07;  // 3-bit priority
    metadata.vlan.dei_flag = (vlanTag >> 12) & 0x01;      // 1-bit DEI flag
    metadata.vlan.inner_ethertype = ntohs(vlanHeader->etherType);

    return true;
} 