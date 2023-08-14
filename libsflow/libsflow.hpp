#pragma once

//
// Upstream version of this file is located at https://github.com/pavel-odintsov/fastnetmon/blob/master/src/libsflow/libsflow.hpp
//
// For clarity we removed all functions for parsing sFlow from it as we have no plans to do so.
//

#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

// TODO: we need to get rid of it
#include <arpa/inet.h>

#include "../fast_endianless.hpp"

// We need it for sanity checks
const uint32_t max_udp_packet_size = 65535;

enum class sflow_sample_type_t : unsigned int {
    FLOW_SAMPLE             = 1,
    COUNTER_SAMPLE          = 2,
    EXPANDED_FLOW_SAMPLE    = 3,
    EXPANDED_COUNTER_SAMPLE = 4,
    BROKEN_TYPE             = UINT_MAX,
};

// This one stores protocol of header https://sflow.org/sflow_version_5.txt
enum sflow_header_protocol {
    SFLOW_HEADER_PROTOCOL_ETHERNET = 1, // Typically, it's Ethernet
    SFLOW_HEADER_PROTOCOL_IPv4     = 11,
    SFLOW_HEADER_PROTOCOL_IPv6     = 12,
};

// Old fashioned not typed enums for fast comparisions and assignments to
// integers
enum sflow_sample_type_not_typed_t {
    SFLOW_SAMPLE_TYPE_FLOW_SAMPLE             = 1,
    SFLOW_SAMPLE_TYPE_COUNTER_SAMPLE          = 2,
    SFLOW_SAMPLE_TYPE_EXPANDED_FLOW_SAMPLE    = 3,
    SFLOW_SAMPLE_TYPE_EXPANDED_COUNTER_SAMPLE = 4,
};

enum sflow_record_types_not_typed_t {
    SFLOW_RECORD_TYPE_RAW_PACKET_HEADER     = 1,
    SFLOW_RECORD_TYPE_EXTENDED_SWITCH_DATA  = 1001,
    SFLOW_RECORD_TYPE_EXTENDED_ROUTER_DATA  = 1002,
    SFLOW_RECORD_TYPE_EXTENDED_GATEWAY_DATA = 1003
};

enum class sample_counter_types_t : unsigned int {
    GENERIC_INTERFACE_COUNTERS  = 1,
    ETHERNET_INTERFACE_COUNTERS = 2,
    BROKEN_COUNTER              = UINT_MAX
};

class __attribute__((__packed__)) sflow_sample_header_as_struct_t {
    public:
    union __attribute__((__packed__)) {
        uint32_t enterprise : 20, sample_type : 12;
        uint32_t enterprise_and_sample_type_as_integer = 0;
    };

    uint32_t sample_length = 0;

    void host_byte_order_to_network_byte_order() {
        enterprise_and_sample_type_as_integer = htonl(enterprise_and_sample_type_as_integer);
        sample_length                         = htonl(sample_length);
    }
};

class __attribute__((__packed__)) sflow_record_header_t {
    public:
    uint32_t record_type   = 0;
    uint32_t record_length = 0;

    void host_byte_order_to_network_byte_order() {
        record_type   = htonl(record_type);
        record_length = htonl(record_length);
    }
};

static_assert(sizeof(sflow_sample_header_as_struct_t) == 8, "Bad size for sflow_sample_header_as_struct_t");
static_assert(sizeof(sflow_record_header_t) == 8, "Bad size for sflow_record_header_t");

// Structure which describes sampled raw ethernet packet from switch
class __attribute__((__packed__)) sflow_raw_protocol_header_t {
    public:
    uint32_t header_protocol{ 0 };
    uint32_t frame_length_before_sampling{ 0 };
    uint32_t number_of_bytes_removed_from_packet{ 0 };
    uint32_t header_size{ 0 };

    // Convert byte order from network to host byte order
    void network_to_host_byte_order() {
        header_protocol                     = fast_ntoh(header_protocol);
        frame_length_before_sampling        = fast_ntoh(frame_length_before_sampling);
        number_of_bytes_removed_from_packet = fast_ntoh(number_of_bytes_removed_from_packet);
        header_size                         = fast_ntoh(header_size);
    }

    // Convert byte order from host to network
    void host_byte_order_to_network_byte_order() {
        header_protocol                     = fast_hton(header_protocol);
        frame_length_before_sampling        = fast_hton(frame_length_before_sampling);
        number_of_bytes_removed_from_packet = fast_hton(number_of_bytes_removed_from_packet);
        header_size                         = fast_hton(header_size);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "header_protocol: " << header_protocol << " "
               << "frame_length_before_sampling: " << frame_length_before_sampling << " "
               << "number_of_bytes_removed_from_packet: " << number_of_bytes_removed_from_packet << " "
               << "header_size: " << header_size << std::endl;

        return buffer.str();
    }
};

class __attribute__((__packed__)) sflow_sample_header_t {
    public:
    uint32_t sample_sequence_number = 0; // sample sequence number
    union __attribute__((__packed__)) {
        uint32_t source_id_with_id_type{ 0 }; // source id type + source id
        uint32_t source_id : 24, source_id_type : 8;
    };
    uint32_t sampling_rate{ 0 }; // sampling ratio
    uint32_t sample_pool{ 0 }; // number of sampled packets
    uint32_t drops_count{ 0 }; // number of drops due to hardware overload
    uint32_t input_port{ 0 }; // input  port + 2 bits port type
    uint32_t output_port{ 0 }; // output port + 2 bits port type
    uint32_t number_of_flow_records{ 0 };

    // Convert all fields to host byte order (little endian)
    void network_to_host_byte_order() {
        sample_sequence_number = fast_ntoh(sample_sequence_number);
        sampling_rate          = fast_ntoh(sampling_rate);
        sample_pool            = fast_ntoh(sample_pool);
        drops_count            = fast_ntoh(drops_count);
        number_of_flow_records = fast_ntoh(number_of_flow_records);

        input_port             = fast_ntoh(input_port);
        output_port            = fast_ntoh(output_port);
        source_id_with_id_type = fast_ntoh(source_id_with_id_type);
    }

    // Convert all fields ti network byte order (big endian)
    void host_byte_order_to_network_byte_order() {
        sample_sequence_number = fast_hton(sample_sequence_number);
        sampling_rate          = fast_hton(sampling_rate);
        sample_pool            = fast_hton(sample_pool);
        drops_count            = fast_hton(drops_count);
        number_of_flow_records = fast_hton(number_of_flow_records);

        input_port             = fast_hton(input_port);
        output_port            = fast_hton(output_port);
        source_id_with_id_type = fast_hton(source_id_with_id_type);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "sampling_rate: " << sampling_rate << " "
               << "sample_pool: " << sample_pool << " "
               << "drops_count: " << drops_count << " "
               << "number_of_flow_records: " << number_of_flow_records;

        return buffer.str();
    }
};

// This header format is really close to "sflow_sample_header_t" but we do not
// encode formats in
// value
class __attribute__((__packed__)) sflow_sample_expanded_header_t {
    public:
    uint32_t sample_sequence_number = 0; // sample sequence number
    uint32_t source_id_type         = 0; // source id type
    uint32_t source_id_index        = 0; // source id index
    uint32_t sampling_rate          = 0; // sampling ratio
    uint32_t sample_pool            = 0; // number of sampled packets
    uint32_t drops_count            = 0; // number of drops due to hardware overload
    uint32_t input_port_type        = 0; // input port type
    uint32_t input_port_index       = 0; // input port index
    uint32_t output_port_type       = 0; // output port type
    uint32_t output_port_index      = 0; // outpurt port index
    uint32_t number_of_flow_records = 0;

    void network_to_host_byte_order() {
        sample_sequence_number = fast_ntoh(sample_sequence_number);
        source_id_type         = fast_ntoh(source_id_type);
        source_id_index        = fast_ntoh(source_id_index);
        sampling_rate          = fast_ntoh(sampling_rate);
        sample_pool            = fast_ntoh(sample_pool);
        drops_count            = fast_ntoh(drops_count);
        input_port_type        = fast_ntoh(input_port_type);
        input_port_index       = fast_ntoh(input_port_index);
        output_port_type       = fast_ntoh(output_port_type);
        output_port_index      = fast_ntoh(output_port_index);
        number_of_flow_records = fast_ntoh(number_of_flow_records);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "sample_sequence_number: " << sample_sequence_number << delimiter << "source_id_type: " << source_id_type
               << delimiter << "source_id_index: " << source_id_index << delimiter << "sampling_rate: " << sampling_rate
               << delimiter << "sample_pool: " << sample_pool << delimiter << "drops_count: " << drops_count << delimiter
               << "input_port_type: " << input_port_type << delimiter << "input_port_index: " << input_port_index << delimiter
               << "output_port_type: " << output_port_type << delimiter << "output_port_index: " << output_port_index
               << delimiter << "number_of_flow_records: " << number_of_flow_records;

        return buffer.str();
    }
};

// IP protocol version use by sflow agent
enum sflow_agent_ip_protocol_version_not_typed : int32_t {
    SFLOW_AGENT_PROTOCOL_VERSION_IPv4 = 1,
    SFLOW_AGENT_PROTOCOL_VERSION_IPV6 = 2,
};

enum sflow_address_type { SFLOW_ADDRESS_TYPE_UNDEFINED = 0, SFLOW_ADDRESS_TYPE_IPv4 = 1, SFLOW_ADDRESS_TYPE_IPV6 = 2 };

// with __attribute__((__packed__)) we have disabled any paddings inside this
// struct
template <std::size_t address_length> class __attribute__((__packed__)) sflow_packet_header {
    public:
    sflow_packet_header() {
        static_assert(address_length == 4 or address_length == 16, "You have specified wrong value for template");
    }
    // 2, 4, 5
    int32_t sflow_version{ 5 };
    // IPv4: 1 (SFLOW_AGENT_PROTOCOL_VERSION_IPv4), IPv6: 2
    // (SFLOW_AGENT_PROTOCOL_VERSION_IPV6)
    int32_t agent_ip_version{ 1 };
    std::array<uint8_t, address_length> address_v4_or_v6{};
    uint32_t sub_agent_id{ 1 };
    uint32_t datagram_sequence_number{ 0 };
    // Device uptime in milliseconds
    uint32_t device_uptime{ 0 };
    uint32_t datagram_samples_count{ 0 };

    // Convert all structure fields to host byte order
    void network_to_host_byte_order() {
        sflow_version            = fast_ntoh(sflow_version);
        agent_ip_version         = fast_ntoh(agent_ip_version);
        sub_agent_id             = fast_ntoh(sub_agent_id);
        datagram_sequence_number = fast_ntoh(datagram_sequence_number);
        device_uptime            = fast_ntoh(device_uptime);
        datagram_samples_count   = fast_ntoh(datagram_samples_count);
    }

    // Convert all structure fields to network byte order
    void host_byte_order_to_network_byte_order() {
        sflow_version            = fast_hton(sflow_version);
        agent_ip_version         = fast_hton(agent_ip_version);
        sub_agent_id             = fast_hton(sub_agent_id);
        datagram_sequence_number = fast_hton(datagram_sequence_number);
        device_uptime            = fast_hton(device_uptime);
        datagram_samples_count   = fast_hton(datagram_samples_count);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sflow_version: " << sflow_version << std::endl
               << "agent_ip_version: " << agent_ip_version << std::endl
               << "sub_agent_id: " << sub_agent_id << std::endl;

        if (address_length == 4) {
            std::string string_ipv4_address;
            build_ipv4_address_from_array(address_v4_or_v6, string_ipv4_address);

            buffer << "agent_ip_address: " << string_ipv4_address << std::endl;
        } else {
            buffer << "agent_ip_address: " << build_ipv6_address_from_array(address_v4_or_v6) << std::endl;
        }

        buffer << "datagram_sequence_number: " << datagram_sequence_number << std::endl
               << "device_uptime: " << device_uptime << std::endl
               << "datagram_samples_count: " << datagram_samples_count << std::endl;

        return buffer.str();
    }
};

using sflow_packet_header_v4_t = sflow_packet_header<4>;
using sflow_packet_header_v6_t = sflow_packet_header<16>;

// This structure keeps information about gateway details, we use it to parse only few first fields
class __attribute__((__packed__)) sflow_extended_gateway_information_t {
    public:
    // Must be IPv4 only, for IPv6 we need another structure
    uint32_t next_hop_address_type = 0;
    uint32_t next_hop              = 0;
    uint32_t router_asn            = 0;
    uint32_t source_asn            = 0;
    uint32_t peer_asn              = 0;
};

class __attribute__((__packed__)) sflow_counter_header_t {
    public:
    uint32_t sample_sequence_number    = 0;
    uint32_t source_type_with_id       = 0;
    uint32_t number_of_counter_records = 0;

    void network_to_host_byte_order() {
        sample_sequence_number    = fast_ntoh(sample_sequence_number);
        source_type_with_id       = fast_ntoh(source_type_with_id);
        number_of_counter_records = fast_ntoh(number_of_counter_records);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_type_with_id: " << source_type_with_id << " "
               << "number_of_counter_records: " << number_of_counter_records << std::endl;

        return buffer.str();
    }
};

// Expanded form of sflow_counter_header_t
class __attribute__((__packed__)) sflow_counter_expanded_header_t {
    public:
    uint32_t sample_sequence_number    = 0;
    uint32_t source_id_type            = 0;
    uint32_t source_id_index           = 0;
    uint32_t number_of_counter_records = 0;

    void network_to_host_byte_order() {
        sample_sequence_number    = fast_ntoh(sample_sequence_number);
        source_id_type            = fast_ntoh(source_id_type);
        source_id_index           = fast_ntoh(source_id_index);
        number_of_counter_records = fast_ntoh(number_of_counter_records);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_id_type: " << source_id_type << " "
               << "source_id_index: " << source_id_index << " "
               << "number_of_counter_records: " << number_of_counter_records << std::endl;

        return buffer.str();
    }
};

class __attribute__((__packed__)) ethernet_sflow_interface_counters_t {
    public:
    uint32_t alignment_errors             = 0;
    uint32_t fcs_errors                   = 0;
    uint32_t single_collision_frames      = 0;
    uint32_t multiple_collision_frames    = 0;
    uint32_t sqe_test_errors              = 0;
    uint32_t deferred_transmissions       = 0;
    uint32_t late_collisions              = 0;
    uint32_t excessive_collisions         = 0;
    uint32_t internal_mac_transmit_errors = 0;
    uint32_t carrier_sense_errors         = 0;
    uint32_t frame_too_longs              = 0;
    uint32_t internal_mac_receive_errors  = 0;
    uint32_t symbol_errors                = 0;

    ethernet_sflow_interface_counters_t(uint8_t* data_pointer) {
        memcpy(this, data_pointer, sizeof(ethernet_sflow_interface_counters_t));
        this->network_to_host_byte_order();
    }

    void network_to_host_byte_order() {
        alignment_errors             = fast_ntoh(alignment_errors);
        fcs_errors                   = fast_ntoh(alignment_errors);
        single_collision_frames      = fast_ntoh(single_collision_frames);
        multiple_collision_frames    = fast_ntoh(multiple_collision_frames);
        sqe_test_errors              = fast_ntoh(sqe_test_errors);
        deferred_transmissions       = fast_ntoh(deferred_transmissions);
        late_collisions              = fast_ntoh(late_collisions);
        excessive_collisions         = fast_ntoh(excessive_collisions);
        internal_mac_transmit_errors = fast_ntoh(internal_mac_transmit_errors);
        carrier_sense_errors         = fast_ntoh(carrier_sense_errors);
        frame_too_longs              = fast_ntoh(frame_too_longs);
        internal_mac_receive_errors  = fast_ntoh(internal_mac_receive_errors);
        symbol_errors                = fast_ntoh(symbol_errors);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "alignment_errors: " << alignment_errors << delimiter << "fcs_errors: " << fcs_errors << delimiter
               << "single_collision_frames: " << single_collision_frames << delimiter
               << "multiple_collision_frames: " << multiple_collision_frames << delimiter << "sqe_test_errors: " << sqe_test_errors
               << delimiter << "deferred_transmissions: " << deferred_transmissions << delimiter
               << "late_collisions: " << late_collisions << delimiter << "excessive_collisions: " << excessive_collisions
               << delimiter << "internal_mac_transmit_errors: " << internal_mac_transmit_errors << delimiter
               << "carrier_sense_errors: " << carrier_sense_errors << delimiter << "frame_too_longs: " << frame_too_longs
               << delimiter << "internal_mac_receive_errors: " << internal_mac_receive_errors << delimiter
               << "symbol_errors: " << symbol_errors;

        return buffer.str();
    }
};

// http://www.sflow.org/SFLOW-STRUCTS5.txt
class __attribute__((__packed__)) generic_sflow_interface_counters_t {
    public:
    uint32_t if_index     = 0;
    uint32_t if_type      = 0;
    uint64_t if_speed     = 0;
    uint32_t if_direction = 0; /* derived from MAU MIB (RFC 2668)
                            0 = unkown, 1=full-duplex, 2=half-duplex,
                            3 = in, 4=out */
    uint32_t if_status = 0; /* bit field with the following bits assigned
                         bit 0 = ifAdminStatus (0 = down, 1 = up)
                         bit 1 = ifOperStatus (0 = down, 1 = up) */
    uint64_t if_in_octets          = 0;
    uint32_t if_in_ucast_pkts      = 0;
    uint32_t if_in_multicast_pkts  = 0;
    uint32_t if_in_broadcast_pkts  = 0;
    uint32_t if_in_discards        = 0;
    uint32_t if_in_errors          = 0;
    uint32_t if_in_unknown_protos  = 0;
    uint64_t if_out_octets         = 0;
    uint32_t if_out_ucast_pkts     = 0;
    uint32_t if_out_multicast_pkts = 0;
    uint32_t if_out_broadcast_pkts = 0;
    uint32_t if_out_discards       = 0;
    uint32_t if_out_errors         = 0;
    uint32_t if_promiscuous_mode   = 0;

    generic_sflow_interface_counters_t(uint8_t* data_pointer) {
        memcpy(this, data_pointer, sizeof(generic_sflow_interface_counters_t));
        this->network_to_host_byte_order();
    }

    void network_to_host_byte_order() {
        if_index              = fast_ntoh(if_index);
        if_type               = fast_ntoh(if_type);
        if_speed              = fast_ntoh(if_speed);
        if_direction          = fast_ntoh(if_direction);
        if_status             = fast_ntoh(if_status);
        if_in_octets          = fast_ntoh(if_in_octets);
        if_in_ucast_pkts      = fast_ntoh(if_in_ucast_pkts);
        if_in_multicast_pkts  = fast_ntoh(if_in_multicast_pkts);
        if_in_broadcast_pkts  = fast_ntoh(if_in_broadcast_pkts);
        if_in_discards        = fast_ntoh(if_in_discards);
        if_in_errors          = fast_ntoh(if_in_errors);
        if_in_unknown_protos  = fast_ntoh(if_in_unknown_protos);
        if_out_octets         = fast_ntoh(if_out_octets);
        if_out_ucast_pkts     = fast_ntoh(if_out_ucast_pkts);
        if_out_multicast_pkts = fast_ntoh(if_out_multicast_pkts);
        if_out_broadcast_pkts = fast_ntoh(if_out_broadcast_pkts);
        if_out_discards       = fast_ntoh(if_out_discards);
        if_out_errors         = fast_ntoh(if_out_errors);
        if_promiscuous_mode   = fast_ntoh(if_promiscuous_mode);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "if_index: " << if_index << delimiter << "if_type: " << if_type << delimiter << "if_speed: " << if_speed
               << delimiter << "if_direction: " << if_direction << delimiter << "if_status: " << if_status << delimiter
               << "if_in_octets: " << if_in_octets << delimiter << "if_in_ucast_pkts: " << if_in_ucast_pkts << delimiter
               << "if_in_multicast_pkts: " << if_in_multicast_pkts << delimiter << "if_in_broadcast_pkts: " << if_in_broadcast_pkts
               << delimiter << "if_in_discards: " << if_in_discards << delimiter << "if_in_errors: " << if_in_errors
               << delimiter << "if_in_unknown_protos: " << if_in_unknown_protos << delimiter
               << "if_out_octets: " << if_out_octets << delimiter << "if_out_ucast_pkts: " << if_out_ucast_pkts << delimiter
               << "if_out_multicast_pkts: " << if_out_multicast_pkts << delimiter << "if_out_broadcast_pkts: " << if_out_broadcast_pkts
               << delimiter << "if_out_discards: " << if_out_discards << delimiter << "if_out_errors: " << if_out_errors
               << delimiter << "if_promiscuous_mode: " << if_promiscuous_mode;

        return buffer.str();
    }
};

static_assert(sizeof(sflow_raw_protocol_header_t) == 16, "Broken size for sflow_raw_protocol_header_t");
static_assert(sizeof(sflow_sample_expanded_header_t) == 44, "Broken size for sflow_sample_expanded_header_t");
static_assert(sizeof(sflow_counter_header_t) == 12, "Broken size for sflow_counter_header_t");
static_assert(sizeof(sflow_counter_expanded_header_t) == 16, "Broken size for sflow_counter_expanded_header_t");
static_assert(sizeof(ethernet_sflow_interface_counters_t) == 52, "Broken size for ethernet_sflow_interface_counters_t");
static_assert(sizeof(generic_sflow_interface_counters_t) == 88, "Broken size for generic_sflow_interface_counters_t");

static_assert(sizeof(sflow_sample_header_t) == 32, "Broken size for sflow_sample_header_t");
static_assert(sizeof(sflow_packet_header_v4_t) == 28, "Broken size for packed IPv4 structure");
static_assert(sizeof(sflow_packet_header_v6_t) == 40, "Broken size for packed IPv6 structure");
