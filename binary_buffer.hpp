#pragma once

#include <cstring>

// This class very similar to packet_storage_t but we store only single memory
// block here and do not
// use dynamic memory allocation
template <std::size_t buffer_size> class binary_buffer_t {
    public:
    // With this structure we could write any data but we need length for it
    bool write_arbitrary_data_size(const void* data, size_t data_length) {
        // Buffer already full
        if (currently_used_space >= buffer_size) {
            errors_occured = true;
            return false;
        }

        // We haven't enough space in buffer for this data
        if (currently_used_space + data_length >= buffer_size) {
            errors_occured = true;
            return false;
        }

        memcpy(internal_buffer + currently_used_space, data, data_length);
        currently_used_space += data_length;

        return true;
    }

    void* get_internal_buffer_address() {
        return internal_buffer;
    }

    size_t get_used_memory() {
        return currently_used_space;
    }

    // If we have any issues with it
    bool is_failed() {
        return errors_occured;
    }

    // With this function we could write structure with specific size
    template <typename src_type> bool write_typed_pointer_data(const src_type* src) {
        return write_arbitrary_data_size(src, sizeof(src_type));
    }

    private:
    size_t currently_used_space = 0;
    // Initilize memory block explicitly by zeroes
    uint8_t internal_buffer[buffer_size] = {};
    // If any erros occured in any time when we used this buffer
    bool errors_occured = false;
};
