#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>
#include <thread>

#include "binary_buffer.hpp"
#include "fast_library.hpp"
#include "libsflow/libsflow.h"
#include "network_data_structures.hpp"

#include <msgpack.hpp>

#include <log4cpp/Appender.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Layout.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>

// For pooling operations
#include <poll.h>

// #include "fastnetmon_packet_parser.h"

#include "readerwriterqueue.h"

// https://github.com/luigirizzo/netmap/issues/46
// TODO: All netmap's includes should be BEFORE any other includes! Because netmap doing some werid definitions which
// broke Boost (I'm speaking about "D")
#define NETMAP_WITH_LIBS
#include "net/netmap_user.h"

std::string log_file_path = "/var/log/fastnetmon_probe.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

using namespace moodycamel;
using namespace network_data_stuctures;

uint32_t sflow_global_sequence_counter = 0;
uint32_t sflow_port_sequence_number    = 0;
uint32_t global_sampling_rate          = 1024;

std::string sflow_target_server = "127.0.0.1";

// We use 1600
const size_t max_packet_size = 1600;

// Prototypes
void generate_msgpack_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data);
void process_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data);
void generate_sflow_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data);

enum class generated_stream_type_t { SFLOW, MSGPACK };

generated_stream_type_t generated_stream_type;

class packet_with_length_t {
    public:
    packet_with_length_t(void* data, size_t data_length) {
        if (data_length > max_packet_size) {
            packet_length = 0;
        } else {
            memcpy(internal_data, data, data_length);
            packet_length = data_length;
        }
    }

    packet_with_length_t() = default;

    uint8_t internal_data[max_packet_size] = {};
    uint16_t packet_length{ 0 };
};

typedef ReaderWriterQueue<packet_with_length_t> lockless_queue_t;

lockless_queue_t eth3_queue(5000);
lockless_queue_t eth4_queue(5000);

int number_of_packets = 0;

/* prototypes */
inline void netmap_thread(struct nm_desc* netmap_descriptor, lockless_queue_t* queue);

inline int receive_packets(struct netmap_ring* ring, lockless_queue_t* queue) {
    // Count number of packets received by this thread
    thread_local uint64_t received_number_of_packets = 0;

    u_int cur, rx, n;

    cur = ring->cur;
    n   = nm_ring_space(ring);

    for (rx = 0; rx < n; rx++) {
        struct netmap_slot* slot = &ring->slot[cur];
        char* p                  = NETMAP_BUF(ring, slot->buf_idx);

        // process data
        // consume_pkt((u_char*)p, slot->len);
        if (received_number_of_packets++ % global_sampling_rate == 0) {
            //__sync_fetch_and_add(&number_of_packets, 1);

            // Add to thread for this process
            bool result = queue->try_enqueue(packet_with_length_t(p, slot->len));

            if (!result) {
                std::cout << "Queue overloaded. Please increase queue size" << std::endl;
            }
        }

        cur = nm_ring_next(ring, cur);
    }

    ring->head = ring->cur = cur;
    return (rx);
}

void receiver(std::string interface, lockless_queue_t* queue) {
    struct nm_desc* netmap_descriptor;

    u_int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("We have %d cpus\n", num_cpus);

    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    netmap_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (netmap_descriptor == NULL) {
        printf("Can't open netmap device %s\n", interface.c_str());
        exit(1);
        return;
    }

    printf("Mapped %dKB memory at %p\n", netmap_descriptor->req.nr_memsize >> 10, netmap_descriptor->mem);
    printf("We have %d tx and %d rx rings\n", netmap_descriptor->req.nr_tx_rings, netmap_descriptor->req.nr_rx_rings);

    /*
        protocol stack and may cause a reset of the card,
        which in turn may take some time for the PHY to
        reconfigure. We do the open here to have time to reset.
    */

    int wait_link = 2;
    printf("Wait %d seconds for NIC reset\n", wait_link);
    sleep(wait_link);

    netmap_thread(netmap_descriptor, queue);
}

inline void netmap_thread(struct nm_desc* netmap_descriptor, lockless_queue_t* queue) {
    struct nm_pkthdr h;
    u_char* buf;
    struct pollfd fds;
    fds.fd     = netmap_descriptor->fd; // NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    struct netmap_ring* rxring = NULL;
    struct netmap_if* nifp     = netmap_descriptor->nifp;

    // printf("Reading from fd %d thread id: %d\n", netmap_descriptor->fd,
    // thread_number);

    for (;;) {
        // We will wait 1000 microseconds for retry, for infinite timeout please use
        // -1
        int poll_result = poll(&fds, 1, 1000);

        if (poll_result == 0) {
            // printf("poll return 0 return code\n");
            continue;
        }

        if (poll_result == -1) {
            printf("poll failed with return code -1\n");
        }

        for (int i = netmap_descriptor->first_rx_ring; i <= netmap_descriptor->last_rx_ring; i++) {
            // printf("Check ring %d from thread %d\n", i, thread_number);
            rxring = NETMAP_RXRING(nifp, i);

            if (nm_ring_empty(rxring)) {
                continue;
            }

            int m = receive_packets(rxring, queue);
        }

        // while ( (buf = nm_nextpkt(netmap_descriptor, &h)) ) {
        //    consume_pkt(buf, h.len);
        //}
    }

    // nm_close(netmap_descriptor);
}

uint64_t eth3_received_packets = 0;
uint64_t eth4_received_packets = 0;

void calculation() {
    for (;;) {
        sleep(1);
        std::cout << "We received packets: " << number_of_packets << std::endl;
        std::cout << "We dequeued packets from eth3: " << eth3_received_packets << std::endl;
        std::cout << "We dequeued packets from eth4: " << eth4_received_packets << std::endl;
        std::cout << "We dequeued packets from eth3 and eth4: " << eth3_received_packets + eth4_received_packets << std::endl;
        number_of_packets     = 0;
        eth3_received_packets = 0;
        eth4_received_packets = 0;
    }
}

void packet_consumer() {
    packet_with_length_t packet;

    // not blocking version
    while (true) {
        bool eth3_res = eth3_queue.try_dequeue(packet);

        if (eth3_res) {
            __sync_fetch_and_add(&eth3_received_packets, 1);
            process_packet(packet.packet_length, packet.internal_data);
        }

        bool eth4_res = eth4_queue.try_dequeue(packet);

        if (eth4_res) {
            __sync_fetch_and_add(&eth4_received_packets, 1);
            process_packet(packet.packet_length, packet.internal_data);
        }

        // Allow for system scheduler to get slice for other processes
        // Not helped us
        // std::this_thread::yield();

        // std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    }
}

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

void process_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data) {
    if (generated_stream_type == generated_stream_type_t::SFLOW) {
        generate_sflow_packet(packet_size_before_sampling, packet_data);
    } else if (generated_stream_type == generated_stream_type_t::MSGPACK) {
        generate_msgpack_packet(packet_size_before_sampling, packet_data);
    }
}

void generate_msgpack_packet(uint32_t packet_size_before_sampling, uint8_t* packet_data) {
    // We are using pointer copy because we are changing it
    uint8_t* local_pointer = packet_data;

    ethernet_header_t* ethernet_header = (ethernet_header_t*)local_pointer;
    ethernet_header->convert();

    local_pointer += sizeof(ethernet_header_t);

    // Skip vlan tag
    if (ethernet_header->ethertype == IanaEthertypeVLAN) {
        ethernet_vlan_header_t* ethernet_vlan_header = (ethernet_vlan_header_t*)local_pointer;
        ethernet_vlan_header->convert();

        local_pointer += sizeof(ethernet_vlan_header_t);

        // Change ethernet ethertype to vlan's ethertype
        ethernet_header->ethertype = ethernet_vlan_header->ethertype;
    }

    // We support only IPv4 here
    if (ethernet_header->ethertype != IanaEthertypeIPv4) {
        return;
    }

    ipv4_header_t* ipv4_header = (ipv4_header_t*)local_pointer;
    ipv4_header->convert();

    msgpack::type::tuple<std::string, std::string, uint32_t> packet_tuple(
        convert_ip_as_little_endian_to_string(ipv4_header->source_ip),
        convert_ip_as_little_endian_to_string(ipv4_header->destination_ip), packet_size_before_sampling);

    std::stringstream buffer;
    msgpack::pack(buffer, packet_tuple);
    buffer.seekg(0);

    std::string data_for_wire(buffer.str());

    send_binary_data_to_udp_server(6343, sflow_target_server.c_str(), data_for_wire.c_str(), data_for_wire.size());
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

    send_binary_data_to_udp_server(6343, sflow_target_server.c_str(), binary_buffer.get_internal_buffer_address(),
                                   binary_buffer.get_used_memory());
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Please specify target protocol (sflow5 ot msgpack) and "
                     "target server IP address"
                  << std::endl;
        return -1;
    }

    std::string target_protocol = argv[1];

    if (target_protocol == "sflow5") {
        generated_stream_type = generated_stream_type_t::SFLOW;
    } else if (target_protocol == "msgpack") {
        generated_stream_type = generated_stream_type_t::MSGPACK;
    } else {
        std::cout << "Unexpected protocol type: " << target_protocol << std::endl;
        return -1;
    }

    sflow_target_server = argv[2];

    std::cout << "We will send " << target_protocol << " stream to server " << sflow_target_server << std::endl;

    init_logging();

    // receiver();
    std::thread first_netmap_thread(receiver, "netmap:eth3/rt", &eth3_queue);
    std::thread second_netmap_thread(receiver, "netmap:eth4/rt", &eth4_queue);
    std::thread calculation_thread(calculation);
    std::thread packet_consumer_thread(packet_consumer);

    first_netmap_thread.join();
    second_netmap_thread.join();

    packet_consumer_thread.join();
    calculation_thread.join();
}
