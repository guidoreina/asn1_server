#ifndef ASN1_BER_DECODER_H
#define ASN1_BER_DECODER_H

#include "asn1/ber/value.h"

namespace asn1 {
  namespace ber {
    // ASN.1 BER decoder.
    class decoder {
      public:
        // Constructor.
        decoder(const void* data, size_t length);
        decoder(const decoder&) = default;

        // Destructor.
        ~decoder() = default;

        // Assignment operator.
        decoder& operator=(const decoder&) = default;

        // Get next object.
        enum class result {
          no_error,
          eof,
          unexpected_eof,
          invalid_tag_number,
          invalid_length,
          max_depth_exceeded,
          max_nested_eoc_exceeded
        };

        result next(value& val);

        // Enter constructed.
        bool enter_constructed();

        // Leave constructed.
        bool leave_constructed();

      private:
        // Maximum depth.
        static constexpr const size_t max_depth = 128;

        // Maximum number of nested end-of-contents.
        static constexpr const size_t max_nested_eoc = 128;

        // Pointer to the data.
        const uint8_t* _M_data;

        // Length.
        size_t _M_length;

        // Offset.
        size_t _M_offset = 0;

        // Was the last value a primitive value?
        bool _M_primitive = true;

        // Constructed.
        struct constructed {
          const uint8_t* data;
          size_t length;

          // Definite length?
          bool definite_length;

          // Contents offset.
          size_t contents_offset;

          // Contents length.
          size_t contents_length;
        };

        constructed _M_constructed[max_depth];

        // Depth.
        size_t _M_depth = 0;

        // Decode tag number.
        result decode_tag_number(uint32_t& tag_number);

        // Decode length.
        result decode_length(size_t depth,
                             size_t& length,
                             bool& definite_length);

        // Find end-of-contents.
        result find_eoc(size_t depth);
    };

    inline decoder::decoder(const void* data, size_t length)
      : _M_data(static_cast<const uint8_t*>(data)),
        _M_length(length)
    {
    }
  }
}

#endif // ASN1_BER_DECODER_H
