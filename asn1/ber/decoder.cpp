#include "asn1/ber/decoder.h"

asn1::ber::decoder::result asn1::ber::decoder::next(value& val)
{
  // If not at the end of the data...
  if (_M_offset < _M_length) {
    // Save initial offset.
    const size_t offset = _M_offset;

    // Save tag class.
    val._M_tag_class =
      static_cast<tag_class>((_M_data[_M_offset] >> 6) & 0x03u);

    // Primitive or constructed?
    val._M_primitive = (_M_data[_M_offset] & 0x20u) == 0;

    // Primitive or the maximum depth has not been reached?
    if ((val._M_primitive) || (_M_depth < max_depth)) {
      // Decode tag number.
      const result res = decode_tag_number(val._M_tag_number);

      // If the tag number could be decoded...
      if (res == result::no_error) {
        // Save whether the encoding is primitive or constructed.
        _M_primitive = val._M_primitive;

        // Decode length.
        bool definite_length;
        const result res = decode_length(0, val._M_length, definite_length);

        // If the length could be decoded...
        if (res == result::no_error) {
          // If the contents octets fit in the buffer...
          if (_M_offset + val._M_length <= _M_length) {
            // Save pointer to the contents octets.
            val._M_data = _M_data + _M_offset;

            // Constructed?
            if (!_M_primitive) {
              _M_constructed[_M_depth].data = _M_data;
              _M_constructed[_M_depth].length = _M_length;

              _M_constructed[_M_depth].definite_length = definite_length;

              _M_constructed[_M_depth].contents_offset = _M_offset;
              _M_constructed[_M_depth].contents_length = val._M_length;
            }

            // Definite length?
            if (definite_length) {
              // Skip contents octets.
              _M_offset += val._M_length;
            } else {
              // Skip contents octets and end-of-contents.
              _M_offset += (val._M_length + 2);
            }

            // Save total length of the value (header + contents octets +
            // end-of-contents octets [optional]).
            val._M_total_length = _M_offset - offset;

            return result::no_error;
          } else {
            return result::unexpected_eof;
          }
        } else {
          return res;
        }
      } else {
        return res;
      }
    } else {
      return result::max_depth_exceeded;
    }
  } else {
    return result::eof;
  }
}

bool asn1::ber::decoder::enter_constructed()
{
  // Constructed?
  if (!_M_primitive) {
    const constructed* const constructed = &_M_constructed[_M_depth++];

    _M_data = constructed->data + constructed->contents_offset;
    _M_length = constructed->contents_length;

    _M_offset = 0;

    return true;
  }

  return false;
}

bool asn1::ber::decoder::leave_constructed()
{
  if (_M_depth > 0) {
    const constructed* const constructed = &_M_constructed[--_M_depth];

    _M_data = constructed->data;
    _M_length = constructed->length;

    // Definite length?
    if (constructed->definite_length) {
      // Skip contents octets.
      _M_offset = constructed->contents_offset + constructed->contents_length;
    } else {
      // Skip contents octets and end-of-contents.
      _M_offset = constructed->contents_offset +
                  constructed->contents_length +
                  2;
    }

    return true;
  }

  return false;
}

asn1::ber::decoder::result
asn1::ber::decoder::decode_tag_number(uint32_t& tag_number)
{
  // Extract tag number and increment offset.
  uint32_t tn = _M_data[_M_offset++] & 0x1fu;

  // If the tag number is smaller than 31...
  if (tn < 31) {
    // Save tag number.
    tag_number = tn;

    return result::no_error;
  }

  tn = 0;

  for (; _M_offset < _M_length; _M_offset++) {
    // If the tag number is not too big...
    if (((tn >> (32 - 7)) & 0x7fu) == 0) {
      tn = (tn << 7) | (_M_data[_M_offset] & 0x7fu);

      // If this is the last byte of the tag number...
      if ((_M_data[_M_offset] & 0x80u) == 0) {
        // Save tag number.
        tag_number = tn;

        // Increment offset.
        _M_offset++;

        return result::no_error;
      }
    } else {
      return result::invalid_tag_number;
    }
  }

  return result::unexpected_eof;
}

asn1::ber::decoder::result
asn1::ber::decoder::decode_length(size_t depth,
                                  size_t& length,
                                  bool& definite_length)
{
  // If not at the end of the data...
  if (_M_offset < _M_length) {
    // If the length fits in seven bits...
    if ((_M_data[_M_offset] & 0x80u) == 0) {
      // Save length and increment offset.
      length = _M_data[_M_offset++];

      definite_length = true;

      return result::no_error;
    }

    // Get the number of subsequent octets and increment the offset.
    const size_t noctets = _M_data[_M_offset++] & 0x7fu;

    // If the number of octets is not too big...
    if (noctets < 5) {
      // If not the indefinite length...
      if (noctets > 0) {
        // If the whole length is in the buffer...
        if (_M_offset + noctets <= _M_length) {
          size_t l = 0;

          for (size_t i = noctets; i > 0; i--) {
            l = (l << 8) | _M_data[_M_offset++];
          }

          length = l;

          definite_length = true;

          return result::no_error;
        } else {
          return result::unexpected_eof;
        }
      } else if (!_M_primitive) {
        // Indefinite length.

        // If the maximum number of nested end-of-contents has not been
        // reached...
        if (depth < max_nested_eoc) {
          // Save current offset (it will be modified in find_eoc()).
          const size_t offset = _M_offset;

          // Find end-of-contents.
          const result res = find_eoc(depth + 1);

          // If not error...
          if (res == result::no_error) {
            // Compute length (`_M_offset` points to end-of-contents).
            length = _M_offset - offset;

            // Restore offset.
            _M_offset = offset;

            definite_length = false;

            return result::no_error;
          } else {
            return res;
          }
        } else {
          return result::max_nested_eoc_exceeded;
        }
      }
    }

    return result::invalid_length;
  } else {
    return result::unexpected_eof;
  }
}

asn1::ber::decoder::result asn1::ber::decoder::find_eoc(size_t depth)
{
  // Save `_M_primitive`.
  const bool primitive = _M_primitive;

  // While the end of the data has not been reached...
  while (_M_offset < _M_length) {
    // Save identifier octet.
    const uint8_t idoctet = _M_data[_M_offset];

    // Decode tag number.
    uint32_t tag_number;
    const result res = decode_tag_number(tag_number);

    // If the tag number could be decoded...
    if (res == result::no_error) {
      // Save whether the encoding is primitive or constructed.
      _M_primitive = (idoctet & 0x20u) == 0;

      // Decode length.
      size_t len;
      bool definite_length;
      const result res = decode_length(depth, len, definite_length);

      // If the length could be decoded...
      if (res == result::no_error) {
        // If the contents octets fit in the buffer...
        if (_M_offset + len <= _M_length) {
          // If not the end-of-contents...
          if (idoctet != 0) {
            // Definite length?
            if (definite_length) {
              // Skip contents octets.
              _M_offset += len;
            } else {
              // Skip contents octets and end-of-contents.
              _M_offset += (len + 2);
            }
          } else {
            if (len == 0) {
              // Restore `_M_primitive`.
              _M_primitive = primitive;

              // Make `_M_offset` point to end-of-contents.
              _M_offset -= 2;

              return result::no_error;
            } else {
              return result::invalid_length;
            }
          }
        } else {
          return result::unexpected_eof;
        }
      } else {
        return res;
      }
    } else {
      return res;
    }
  }

  return result::unexpected_eof;
}
