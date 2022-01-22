#ifndef ASN1_BER_ENCODER_H
#define ASN1_BER_ENCODER_H

#include <sys/time.h>
#include "asn1/ber/tag.h"
#include "string/buffer.h"

namespace asn1 {
  namespace ber {
    // ASN.1 BER encoder.
    class encoder {
      public:
        // Copy.
        enum class copy {
          shallow,
          deep
        };

        // Constructor.
        encoder() = default;

        // Destructor.
        ~encoder() = default;

        // Add boolean.
        bool add_boolean(tag_class tc, uint32_t tn, bool val);

        // Add integer.
        bool add_integer(tag_class tc, uint32_t tn, int64_t val);

        // Add data.
        bool add_data(tag_class tc,
                      uint32_t tn,
                      const void* val,
                      size_t len,
                      copy cp = copy::deep);

        // Add null.
        bool add_null(tag_class tc, uint32_t tn);

        // Start constructed.
        bool start_constructed(tag_class tc, uint32_t tn);

        // End constructed.
        bool end_constructed();

        // Add generalized time.
        bool add_generalized_time(tag_class tc,
                                  uint32_t tn,
                                  const struct timeval& tv);

        // Add generalized time using current time.
        bool add_generalized_time(tag_class tc, uint32_t tn);

        // Serialize.
        bool serialize(string::buffer& buf) const;
        bool serialize(const char* filename) const;

      private:
        // Maximum number of values.
        static constexpr const size_t max_values = 256;

        // Value.
        class value {
          public:
            // Constructor.
            value() = default;

            // Destructor.
            ~value();

            // Get total length.
            size_t total_length() const;

            // Get parent.
            ssize_t parent() const;

            // Set parent.
            void parent(ssize_t p);

            // Set value length.
            void value_length(size_t valuelen);

            // Encode boolean.
            void encode_boolean(tag_class tc, uint32_t tn, bool val);

            // Encode integer.
            void encode_integer(tag_class tc, uint32_t tn, int64_t val);

            // Encode data.
            bool encode_data(tag_class tc,
                             uint32_t tn,
                             const void* val,
                             size_t len,
                             copy cp);

            // Encode null.
            void encode_null(tag_class tc, uint32_t tn);

            // Encode constructed.
            void encode_constructed(tag_class tc, uint32_t tn);


            // Encode generalized time.
            void encode_generalized_time(tag_class tc,
                                         uint32_t tn,
                                         const struct timeval& tv);

            // Serialize.
            bool serialize(string::buffer& buf) const;

          private:
            // Encoded tag.
            uint8_t _M_tag[6];

            // Length of the encoded tag.
            size_t _M_taglen;

            // Primitive?
            bool _M_primitive;

            // Encoded length.
            uint8_t _M_len[9];

            // Length of the encoded length.
            size_t _M_lenlen;

            // Value type.
            enum class type {
              value,
              const_pointer,
              pointer,
              constructed
            };

            type _M_type = type::value;

            // Value.
            union {
              // Encoded value.
              uint8_t v[23];

              const void* cdata;
              void* data;
            } _M_value;

            // Length of the value.
            size_t _M_valuelen;

            // Index of the parent value (-1 if it has no parent).
            ssize_t _M_parent;

            // Encode identifier octets.
            void encode_identifier_octets(tag_class tc,
                                          bool primitive,
                                          uint32_t tn);

            // Encode tag number.
            void encode_tag_number(uint32_t tn);

            // Encode length.
            void encode_length(size_t len);

            // Disable copy constructor and assignment operator.
            value(const value&) = delete;
            value& operator=(const value&) = delete;
        };

        // Values.
        value _M_values[max_values];
        size_t _M_nvalues = 0;

        // Parent.
        ssize_t _M_parent = -1;

        // Disable copy constructor and assignment operator.
        encoder(const encoder&) = delete;
        encoder& operator=(const encoder&) = delete;
    };
  }
}

#endif // ASN1_BER_ENCODER_H
