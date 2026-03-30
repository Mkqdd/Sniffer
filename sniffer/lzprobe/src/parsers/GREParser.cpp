#include "parsers/GREParser.h"
#include "parsers/IPv4Parser.h"
#include "parsers/IPv6Parser.h"
#include "parsers/VLANParser.h"
#include "parsers/TCPParser.h"
#include "parsers/UDPParser.h"
#include "parsers/EthernetParser.h"
#include "parsers/ICMPParser.h"
#include <pcapplusplus/GreLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/PacketUtils.h>
#include <netinet/in.h>

bool GREParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* greLayer = packet.getLayerOfType<pcpp::GreLayer>();
    if (!greLayer) {
        return false;
    }

    // Mark that GRE is present
    metadata.has_gre = true;
    
    // Try to cast to specific GRE layer types to determine version
    auto* grev0Layer = dynamic_cast<pcpp::GREv0Layer*>(greLayer);
    auto* grev1Layer = dynamic_cast<pcpp::GREv1Layer*>(greLayer);
    
    if (grev0Layer) {
        // Parse GREv0 layer
        return parseGREv0(grev0Layer, packet, metadata);
    } else if (grev1Layer) {
        // Parse GREv1 layer
        return parseGREv1(grev1Layer, packet, metadata);
    }
    
    // Fallback: try to parse as generic GRE layer
    return parseGenericGRE(greLayer, packet, metadata);
}

bool GREParser::parseGREv0(pcpp::GREv0Layer* grev0Layer, pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* greHeader = grev0Layer->getGreHeader();
    if (!greHeader) {
        return false;
    }
    
    // Set GRE version
    metadata.gre.version = 0;
    
    // Parse basic header fields
    metadata.gre.protocol = ntohs(greHeader->protocol);
    metadata.gre.recursion_control = greHeader->recursionControl;
    metadata.gre.checksum_bit = greHeader->checksumBit;
    metadata.gre.routing_bit = greHeader->routingBit;
    metadata.gre.key_bit = greHeader->keyBit;
    metadata.gre.sequence_bit = greHeader->sequenceNumBit;
    metadata.gre.strict_source_route = greHeader->strictSourceRouteBit;
    metadata.gre.ack_sequence_bit = false; // Not available in GREv0
    
    // Parse optional fields if they exist
    if (metadata.gre.checksum_bit) {
        uint16_t checksum;
        if (grev0Layer->getChecksum(checksum)) {
            metadata.gre.checksum = checksum;
        }
    }
    
    if (metadata.gre.routing_bit) {
        uint16_t offset;
        if (grev0Layer->getOffset(offset)) {
            metadata.gre.offset = offset;
        }
    }
    
    if (metadata.gre.key_bit) {
        uint32_t key;
        if (grev0Layer->getKey(key)) {
            metadata.gre.key = key;
        }
    }
    
    if (metadata.gre.sequence_bit) {
        uint32_t sequence;
        if (grev0Layer->getSequenceNumber(sequence)) {
            metadata.gre.sequence = sequence;
        }
    }
    
    // GREv1 specific fields are not applicable
    metadata.gre.payload_length = 0;
    metadata.gre.call_id = 0;
    
    // Parse the encapsulated protocol after GRE
    return parseEncapsulatedProtocol(packet, metadata);
}

bool GREParser::parseGREv1(pcpp::GREv1Layer* grev1Layer, pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* greHeader = grev1Layer->getGreHeader();
    if (!greHeader) {
        return false;
    }
    
    // Set GRE version
    metadata.gre.version = 1;
    
    // Parse basic header fields
    metadata.gre.protocol = ntohs(greHeader->protocol);
    metadata.gre.recursion_control = greHeader->recursionControl;
    metadata.gre.checksum_bit = greHeader->checksumBit;
    metadata.gre.routing_bit = greHeader->routingBit;
    metadata.gre.key_bit = greHeader->keyBit;
    metadata.gre.sequence_bit = greHeader->sequenceNumBit;
    metadata.gre.strict_source_route = greHeader->strictSourceRouteBit;
    metadata.gre.ack_sequence_bit = greHeader->ackSequenceNumBit; // Available in GREv1
    
    // GREv1 specific fields - get from header directly
    metadata.gre.payload_length = ntohs(greHeader->payloadLength);
    metadata.gre.call_id = ntohs(greHeader->callID);
    
    // Parse the encapsulated protocol after GRE
    return parseEncapsulatedProtocol(packet, metadata);
}

bool GREParser::parseGenericGRE(pcpp::GreLayer* greLayer, pcpp::Packet& packet, PacketMetadata& metadata) {
    // For generic GRE parsing, we'll set basic information
    metadata.gre.protocol = 0; // We can't determine this without header access
    metadata.gre.version = 0; // Assume GREv0 for generic parsing
    
    // Parse the encapsulated protocol after GRE
    return parseEncapsulatedProtocol(packet, metadata);
}

bool GREParser::parseEncapsulatedProtocol(pcpp::Packet& packet, PacketMetadata& metadata) {
    // After GRE, we just mark what types of encapsulated protocols are present
    // but don't parse them recursively to avoid infinite loops
    
    // Check what's encapsulated inside GRE and record it
    if (packet.isPacketOfType(pcpp::IPv4)) {
        // IPv4 is encapsulated - this will be parsed by the main parsing loop
        return true;
    } else if (packet.isPacketOfType(pcpp::IPv6)) {
        // IPv6 is encapsulated - this will be parsed by the main parsing loop
        return true;
    } else if (packet.isPacketOfType(pcpp::Ethernet)) {
        // Ethernet is encapsulated - this will be parsed by the main parsing loop
        return true;
    }
    
    return true; // GRE parsing succeeded
} 