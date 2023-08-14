#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <stdio.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include "binary_buffer.hpp"

#include "libsflow/libsflow.hpp"

std::string log_file_path = "/var/log/fastnetmon_probe.log";

uint32_t sflow_global_sequence_counter = 0;
uint32_t sflow_port_sequence_number    = 0;
uint32_t global_sampling_rate          = 1024;

std::string sflow_target_server = "127.0.0.1";

// Assume default packet size
const size_t max_packet_size = 1500;

// Prototypes
void process_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data);
void generate_sflow_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data);

int number_of_packets = 0;

void calculation() {
    for (;;) {
        sleep(1);
        std::cout << "We received packets: " << number_of_packets << std::endl;
        number_of_packets     = 0;
    }
}

bool execute_conection(int protocol, uint16_t remote_server_port, const std::string& remote_host, int& socket_fd_answer) {
    int client_sockfd = socket(AF_INET, protocol, 0);

    if (client_sockfd < 0) {
        return false;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(remote_server_port);

    int pton_result = inet_pton(AF_INET, remote_host.c_str(), &serv_addr.sin_addr);

    if (pton_result <= 0) {
        close(client_sockfd);
        return false;
    }

    int connect_result = connect(client_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if (connect_result < 0) {
        close(client_sockfd);
        return false;
    }

    // Return connected socket
    socket_fd_answer = client_sockfd;
    return true;
}


bool send_binary_data_to_server(int protocol, uint16_t remote_server_port, const std::string& remote_host, const void* data, size_t data_length) {
    int client_sockfd = 0;

    bool connect_result = execute_conection(protocol, remote_server_port, remote_host, client_sockfd);

    if (!connect_result) {
        return false;
    }

    int write_result = write(client_sockfd, data, data_length);

    close(client_sockfd);

    if (write_result <= 0) {
        return false;
    }

    return true;
}

uint64_t get_server_uptime_in_seconds() {
    struct sysinfo current_server_sysinfo;
    memset(&current_server_sysinfo, 0, sizeof(current_server_sysinfo));

    int sysinfo_result = sysinfo(&current_server_sysinfo);

    if (sysinfo_result != 0) {
        return 0;
    }

    return (uint64_t)current_server_sysinfo.uptime;
}

void generate_sflow_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data) {
    // How much bytes we will remove from original packet?
    uint32_t removed_bytes = 0;

    if (packet_size_before_sampling > 100) {
        // For bigger packets we reduce packet size to lowest number near to 4-byte
        // bounds
        removed_bytes = packet_size_before_sampling - 100;
    } else {
        // According to Wireshark sources (epan/dissectors/packet-sflow.c) we should
        // store only
        // header part with size multiplied by 4 bytes.
        // More details: https://groups.google.com/forum/#!topic/sflow/AVT_zkKv2QA
        uint32_t division_remainder = packet_size_before_sampling % 4;

        if (division_remainder != 0) {
            removed_bytes = division_remainder;
        } else {
            removed_bytes = 0;
        }
    }

    // std::cout << "Original packet size " << packet_size_before_sampling << " we
    // want to remove "
    // << removed_bytes << " from it" << std::endl;

    // std::cout << "I want to remove " << removed_bytes << " bytes from original
    // packet for 4-byte
    // alignment" << std::endl;

    uint32_t cropped_packet_size = packet_size_before_sampling - removed_bytes;

    // We assume no vlan tagging on interface!
    size_t mtu = max_packet_size;

    // Increment sflow sequence number
    sflow_global_sequence_counter++;

    sflow_packet_header_v4_t sflow_packet;

    sflow_packet.sflow_version    = 5;
    sflow_packet.agent_ip_version = SFLOW_AGENT_PROTOCOL_VERSION_IPv4;
    sflow_packet.address_v4_or_v6 = { 127, 0, 0, 1 };

    // Eth interface internal number (?)
    sflow_packet.sub_agent_id             = 1;
    sflow_packet.datagram_sequence_number = sflow_global_sequence_counter;
    sflow_packet.device_uptime            = uint32_t(get_server_uptime_in_seconds() * 1000);

    // Number of samples in packet
    sflow_packet.datagram_samples_count = 1;

    sflow_packet.host_byte_order_to_network_byte_order();

    // size_t technical_packet_payload = sizeof(ethernet_header_t) +
    // sizeof(ipv4_header_t) +
    // sizeof(udp_header_t) +sizeof(sflow_packet);
    // size_t free_space_in_packet = mtu - technical_packet_payload;
    // std::cout << "We have " << free_space_in_packet << " bytes in packet" <<
    // std::endl;

    // Prepare sample header
    sflow_sample_header_as_struct_t sample_header;
    sample_header.enterprise    = 0;
    sample_header.sample_type   = SFLOW_SAMPLE_TYPE_FLOW_SAMPLE;
    sample_header.sample_length = sizeof(sflow_sample_header_t) + sizeof(sflow_record_header_t) +
                                  sizeof(sflow_raw_protocol_header_t) + cropped_packet_size;

    sample_header.host_byte_order_to_network_byte_order();

    sflow_port_sequence_number++;

    // Prepare sflow flow header
    sflow_sample_header_t sflow_sample_header;
    // We handle per port seq numbers
    sflow_sample_header.sample_sequence_number = sflow_port_sequence_number;
    // I do not know what zero means here but everybody uses it
    sflow_sample_header.source_id_type = 0;
    // Identification for sflow data source
    sflow_sample_header.source_id     = 5;
    sflow_sample_header.sampling_rate = global_sampling_rate;
    // Number of observed packets for all time
    sflow_sample_header.sample_pool = 12312323;
    sflow_sample_header.drops_count = 0;
    sflow_sample_header.input_port  = 1;
    sflow_sample_header.output_port = 2;
    // for test time
    sflow_sample_header.number_of_flow_records = 1;

    sflow_sample_header.host_byte_order_to_network_byte_order();

    sflow_record_header_t sflow_record_header;
    sflow_record_header.record_type   = SFLOW_RECORD_TYPE_RAW_PACKET_HEADER;
    sflow_record_header.record_length = sizeof(sflow_raw_protocol_header_t) + cropped_packet_size;

    sflow_record_header.host_byte_order_to_network_byte_order();

    sflow_raw_protocol_header_t sflow_raw_protocol_header;
    // 1 means ETHERNET
    sflow_raw_protocol_header.header_protocol = 1;
    // We store whole packet
    sflow_raw_protocol_header.frame_length_before_sampling = packet_size_before_sampling;
    // We store whole packet
    sflow_raw_protocol_header.number_of_bytes_removed_from_packet = removed_bytes;

    // Remove two bytes for aligning purposes
    sflow_raw_protocol_header.header_size = cropped_packet_size;

    sflow_raw_protocol_header.host_byte_order_to_network_byte_order();

    binary_buffer_t<1500> binary_buffer;

    binary_buffer.write_typed_pointer_data(&sflow_packet);
    binary_buffer.write_typed_pointer_data(&sample_header);
    binary_buffer.write_typed_pointer_data(&sflow_sample_header);
    binary_buffer.write_typed_pointer_data(&sflow_record_header);
    binary_buffer.write_typed_pointer_data(&sflow_raw_protocol_header);
    binary_buffer.write_arbitrary_data_size(packet_data, cropped_packet_size);

    if (binary_buffer.is_failed()) {
        std::cout << "We have problems with binary buffer, please check it" << std::endl;
        return;
    }

    // std::cout << "We have binary buffer with size: " <<
    // binary_buffer.get_used_memory() <<
    // std::endl;

    send_binary_data_to_server(SOCK_DGRAM, 6343, sflow_target_server.c_str(), binary_buffer.get_internal_buffer_address(), binary_buffer.get_used_memory());
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Please specify target protocol (sflow5 only) and "
                     "target server IP address"
                  << std::endl;
        return -1;
    }

    std::string target_protocol = argv[1];

    if (target_protocol == "sflow5") {
    } else {
        std::cout << "Unexpected protocol type: " << target_protocol << std::endl;
        return -1;
    }

    sflow_target_server = argv[2];

    std::cout << "We will send " << target_protocol << " stream to server " << sflow_target_server << std::endl;

    // TODO: Add logic to consume packets from interface

    std::thread calculation_thread(calculation);

    calculation_thread.join();
}
