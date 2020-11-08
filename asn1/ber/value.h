#ifndef ASN1_BER_VALUE_H
#define ASN1_BER_VALUE_H

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include "asn1/ber/tag.h"

namespace asn1 {
  namespace ber {
    // ASN.1 data value.
    class value {
      friend class decoder;

      public:
        // Maximum number of object identifier components.
        static constexpr const size_t max_oid_components = 64;

        // Constructor.
        value() = default;
        value(const value&) = default;

        // Destructor.
        ~value() = default;

        // Assignment operator.
        value& operator=(const value&) = default;

        // Get total length of the value (header + contents).
        size_t total_length() const;

        // Get tag class.
        enum tag_class tag_class() const;

        // Is primitive?
        bool primitive() const;

        // Is constructed?
        bool constructed() const;

        // Get tag number.
        uint32_t tag_number() const;

        // Get data value.
        const void* data() const;

        // Get length of the contents octets.
        size_t length() const;

        // Decode boolean.
        bool decode_boolean(bool& val) const;

        // Decode integer.
        bool decode_integer(int64_t& val) const;

        // Decode null.
        bool decode_null() const;

        // Decode object identifier.
        bool decode_oid(uint32_t* components, size_t& ncomponents) const;

        // Decode enumerated.
        bool decode_enumerated(int64_t& val) const;

        // Decode UTC time.
        bool decode_utc_time(time_t& val) const;

        // Decode generalized time.
        bool decode_generalized_time(struct timeval& val) const;

      private:
        // Total length of the value (header + contents).
        size_t _M_total_length;

        // Tag class.
        enum tag_class _M_tag_class;

        // Primitive?
        bool _M_primitive;

        // Tag number.
        uint32_t _M_tag_number;

        const uint8_t* _M_data;
        size_t _M_length;
    };

    inline size_t value::total_length() const
    {
      return _M_total_length;
    }

    inline enum tag_class value::tag_class() const
    {
      return _M_tag_class;
    }

    inline bool value::primitive() const
    {
      return _M_primitive;
    }

    inline bool value::constructed() const
    {
      return !_M_primitive;
    }

    inline uint32_t value::tag_number() const
    {
      return _M_tag_number;
    }

    inline const void* value::data() const
    {
      return _M_data;
    }

    inline size_t value::length() const
    {
      return _M_length;
    }

    inline bool value::decode_enumerated(int64_t& val) const
    {
      return decode_integer(val);
    }
  }
}

#endif // ASN1_BER_VALUE_H
