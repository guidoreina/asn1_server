#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "asn1/ber/encoder.h"

#if !defined(_WIN32)
  #define O_BINARY 0
#endif

bool asn1::ber::encoder::add_boolean(tag_class tc, uint32_t tn, bool val)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode boolean.
    v->encode_boolean(tc, tn, val);

    // Set value's parent.
    v->parent(_M_parent);

    // Increment number of values.
    _M_nvalues++;

    return true;
  }

  return true;
}

bool asn1::ber::encoder::add_integer(tag_class tc, uint32_t tn, int64_t val)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode integer.
    v->encode_integer(tc, tn, val);

    // Set value's parent.
    v->parent(_M_parent);

    // Increment number of values.
    _M_nvalues++;

    return true;
  }

  return true;
}

bool asn1::ber::encoder::add_data(tag_class tc,
                                  uint32_t tn,
                                  const void* val,
                                  size_t len,
                                  copy cp)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode data.
    if (v->encode_data(tc, tn, val, len, cp)) {
      // Set value's parent.
      v->parent(_M_parent);

      // Increment number of values.
      _M_nvalues++;

      return true;
    }
  }

  return true;
}

bool asn1::ber::encoder::add_null(tag_class tc, uint32_t tn)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode null.
    v->encode_null(tc, tn);

    // Set value's parent.
    v->parent(_M_parent);

    // Increment number of values.
    _M_nvalues++;

    return true;
  }

  return true;
}

bool asn1::ber::encoder::start_constructed(tag_class tc, uint32_t tn)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode constructed.
    v->encode_constructed(tc, tn);

    // Set value's parent.
    v->parent(_M_parent);

    _M_parent = _M_nvalues;

    // Increment number of values.
    _M_nvalues++;

    return true;
  }

  return true;
}

bool asn1::ber::encoder::end_constructed()
{
  if (_M_parent != -1) {
    // Compute the length of the constructed value.
    size_t valuelen = 0;
    for (size_t i = _M_parent + 1; i < _M_nvalues; i++) {
      // If the value is a child value of the current parent...
      if (_M_values[i].parent() == _M_parent) {
        valuelen += _M_values[i].total_length();
      }
    }

    // Set value length.
    _M_values[_M_parent].value_length(valuelen);

    _M_parent = _M_values[_M_parent].parent();

    return true;
  }

  return false;
}

bool asn1::ber::encoder::add_generalized_time(tag_class tc,
                                              uint32_t tn,
                                              const struct timeval& tv)
{
  // If there are not too many values...
  if (_M_nvalues < max_values) {
    value* const v = &_M_values[_M_nvalues];

    // Encode generalized time.
    v->encode_generalized_time(tc, tn, tv);

    // Set value's parent.
    v->parent(_M_parent);

    // Increment number of values.
    _M_nvalues++;

    return true;
  }

  return true;
}

bool asn1::ber::encoder::add_generalized_time(tag_class tc, uint32_t tn)
{
  // Get current time.
  struct timeval tv;
  gettimeofday(&tv, nullptr);

  return add_generalized_time(tc, tn, tv);
}

bool asn1::ber::encoder::serialize(string::buffer& buf) const
{
  if (_M_parent == -1) {
    // For each value...
    for (size_t i = 0; i < _M_nvalues; i++) {
      // Serialize value.
      if (!_M_values[i].serialize(buf)) {
        return false;
      }
    }

    return true;
  }

  return false;
}

bool asn1::ber::encoder::serialize(const char* filename) const
{
  // Serialize to buffer.
  string::buffer buf;
  if (serialize(buf)) {
    // Open file for writing.
    const int fd = open(filename,
                        O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
                        0644);

    // If the file could be opened...
    if (fd != -1) {
      const uint8_t* data = static_cast<const uint8_t*>(buf.data());

      size_t left = buf.length();

      // While there is data to be written to the file...
      while (left > 0) {
        // Write to the file.
        const ssize_t ret = write(fd, data, left);

        // If we have written some data...
        if (ret > 0) {
          data += ret;
          left -= ret;
        } else if (ret < 0) {
          if (errno != EINTR) {
            close(fd);
            unlink(filename);

            return false;
          }
        }
      }

      close(fd);

      return true;
    }
  }

  return false;
}

asn1::ber::encoder::value::~value()
{
  if (_M_type == type::pointer) {
    free(_M_value.data);
  }
}

size_t asn1::ber::encoder::value::total_length() const
{
  return _M_taglen + _M_lenlen + _M_valuelen;
}

ssize_t asn1::ber::encoder::value::parent() const
{
  return _M_parent;
}

void asn1::ber::encoder::value::parent(ssize_t p)
{
  _M_parent = p;
}

void asn1::ber::encoder::value::value_length(size_t valuelen)
{
  // Encode length.
  encode_length(valuelen);
}

void asn1::ber::encoder::value::encode_boolean(tag_class tc,
                                               uint32_t tn,
                                               bool val)
{
  // Encode identifier octets.
  encode_identifier_octets(tc, true, tn);

  // Encode length.
  _M_len[0] = 1;
  _M_lenlen = 1;

  _M_type = type::value;

  // Encode value.
  _M_value.v[0] = static_cast<uint8_t>(val ? 0xff : 0x00);
  _M_valuelen = 1;
}

void asn1::ber::encoder::value::encode_integer(tag_class tc,
                                               uint32_t tn,
                                               int64_t val)
{
  // Encode identifier octets.
  encode_identifier_octets(tc, true, tn);

  _M_type = type::value;

  if ((val < 0x80ll) && (val >= -0x80ll)) {
    // Encode length.
    _M_len[0] = 1;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>(val);
    _M_valuelen = 1;
  } else if ((val < 0x8000ll) && (val >= -0x8000ll)) {
    // Encode length.
    _M_len[0] = 2;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 2;
  } else if ((val < 0x800000ll) && (val >= -0x800000ll)) {
    // Encode length.
    _M_len[0] = 3;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 3;
  } else if ((val < 0x80000000ll) && (val >= -0x80000000ll)) {
    // Encode length.
    _M_len[0] = 4;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 24) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[3] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 4;
  } else if ((val < 0x8000000000ll) && (val >= -0x8000000000ll)) {
    // Encode length.
    _M_len[0] = 5;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 32) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 24) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[3] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[4] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 5;
  } else if ((val < 0x800000000000ll) && (val >= -0x800000000000ll)) {
    // Encode length.
    _M_len[0] = 6;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 40) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 32) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>((val >> 24) & 0xff);
    _M_value.v[3] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[4] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[5] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 6;
  } else if ((val < 0x80000000000000ll) && (val >= -0x80000000000000ll)) {
    // Encode length.
    _M_len[0] = 7;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 48) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 40) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>((val >> 32) & 0xff);
    _M_value.v[3] = static_cast<uint8_t>((val >> 24) & 0xff);
    _M_value.v[4] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[5] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[6] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 7;
  } else {
    // Encode length.
    _M_len[0] = 8;
    _M_lenlen = 1;

    // Encode value.
    _M_value.v[0] = static_cast<uint8_t>((val >> 56) & 0xff);
    _M_value.v[1] = static_cast<uint8_t>((val >> 48) & 0xff);
    _M_value.v[2] = static_cast<uint8_t>((val >> 40) & 0xff);
    _M_value.v[3] = static_cast<uint8_t>((val >> 32) & 0xff);
    _M_value.v[4] = static_cast<uint8_t>((val >> 24) & 0xff);
    _M_value.v[5] = static_cast<uint8_t>((val >> 16) & 0xff);
    _M_value.v[6] = static_cast<uint8_t>((val >> 8) & 0xff);
    _M_value.v[7] = static_cast<uint8_t>(val & 0xff);

    _M_valuelen = 8;
  }
}

bool asn1::ber::encoder::value::encode_data(tag_class tc,
                                            uint32_t tn,
                                            const void* data,
                                            size_t len,
                                            copy cp)
{
  if (cp == copy::deep) {
    if ((_M_value.data = malloc(len)) != nullptr) {
      memcpy(_M_value.data, data, len);
      _M_type = type::pointer;
    } else {
      return false;
    }
  } else {
    _M_value.cdata = data;
    _M_type = type::const_pointer;
  }

  // Encode identifier octets.
  encode_identifier_octets(tc, true, tn);

  // Encode length.
  encode_length(len);

  return true;
}

void asn1::ber::encoder::value::encode_null(tag_class tc, uint32_t tn)
{
  // Encode identifier octets.
  encode_identifier_octets(tc, true, tn);

  // Encode length.
  _M_lenlen = 0;

  _M_type = type::value;

  _M_valuelen = 0;
}

void asn1::ber::encoder::value::encode_constructed(tag_class tc, uint32_t tn)
{
  // Encode identifier octets.
  encode_identifier_octets(tc, false, tn);

  _M_lenlen = 0;
  _M_valuelen = 0;

  _M_type = type::constructed;
}

void
asn1::ber::encoder::value::encode_generalized_time(tag_class tc,
                                                   uint32_t tn,
                                                   const struct timeval& tv)
{
  // Encode identifier octets.
  encode_identifier_octets(tc, true, tn);

  struct tm tm;

#if !defined(_WIN32)
  gmtime_r(&tv.tv_sec, &tm);
#else
  const time_t sec = tv.tv_sec;
  gmtime_s(&tm, &sec);
#endif

  // If there are microseconds...
  if (tv.tv_usec != 0) {
    _M_valuelen = snprintf(reinterpret_cast<char*>(_M_value.v),
                           sizeof(_M_value.v),
                           "%04u%02u%02u%02u%02u%02u.",
                           1900 + tm.tm_year,
                           1 + tm.tm_mon,
                           tm.tm_mday,
                           tm.tm_hour,
                           tm.tm_min,
                           tm.tm_sec);

    unsigned usec = tv.tv_usec;
    unsigned div = 100000;

    while (usec != 0) {
      _M_value.v[_M_valuelen++] = '0' + (usec / div);

      usec %= div;
      div /= 10;
    }

    _M_value.v[_M_valuelen++] = 'Z';
  } else {
    _M_valuelen = snprintf(reinterpret_cast<char*>(_M_value.v),
                           sizeof(_M_value.v),
                           "%04u%02u%02u%02u%02u%02uZ",
                           1900 + tm.tm_year,
                           1 + tm.tm_mon,
                           tm.tm_mday,
                           tm.tm_hour,
                           tm.tm_min,
                           tm.tm_sec);
  }

  // Encode length.
  _M_len[0] = static_cast<uint8_t>(_M_valuelen);
  _M_lenlen = 1;

  _M_type = type::value;
}

bool asn1::ber::encoder::value::serialize(string::buffer& buf) const
{
  // Serialize tag and length.
  if ((buf.append(_M_tag, _M_taglen)) && (buf.append(_M_len, _M_lenlen))) {
    switch (_M_type) {
      case type::value:
        return buf.append(_M_value.v, _M_valuelen);
      case type::const_pointer:
        return buf.append(_M_value.cdata, _M_valuelen);
      case type::pointer:
        return buf.append(_M_value.data, _M_valuelen);
      case type::constructed:
        return true;
    }
  }

  return false;
}

void asn1::ber::encoder::value::encode_identifier_octets(tag_class tc,
                                                         bool primitive,
                                                         uint32_t tn)
{
  // Set tag class.
  _M_tag[0] = static_cast<uint8_t>(tc) << 6;

  // Constructed?
  if (!primitive) {
    _M_tag[0] |= 0x20;
  }

  // If the tag number is not too big...
  if (tn < 31) {
    _M_tag[0] |= static_cast<uint8_t>(tn);

    _M_taglen = 1;
  } else {
    _M_tag[0] |= 0x01f;

    encode_tag_number(tn);
  }
}

void asn1::ber::encoder::value::encode_tag_number(uint32_t tn)
{
  if (tn < 0x80u) {
    _M_tag[1] = static_cast<uint8_t>(tn);

    _M_taglen = 2;
  } else if (tn < 0x4000u) {
    _M_tag[1] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
    _M_tag[2] = static_cast<uint8_t>(tn & 0x7f);

    _M_taglen = 3;
  } else if (tn < 0x200000u) {
    _M_tag[1] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
    _M_tag[2] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
    _M_tag[3] = static_cast<uint8_t>(tn & 0x7f);

    _M_taglen = 4;
  } else if (tn < 0x10000000u) {
    _M_tag[1] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
    _M_tag[2] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
    _M_tag[3] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
    _M_tag[4] = static_cast<uint8_t>(tn & 0x7f);

    _M_taglen = 5;
  } else {
    _M_tag[1] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
    _M_tag[2] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
    _M_tag[3] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
    _M_tag[4] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
    _M_tag[5] = static_cast<uint8_t>(tn & 0x7f);

    _M_taglen = 6;
  }
}

void asn1::ber::encoder::value::encode_length(size_t len)
{
  if (len <= 0x7full) {
    _M_len[0] = static_cast<uint8_t>(len);

    _M_lenlen = 1;
  } else if (len <= 0xffull) {
    _M_len[0] = static_cast<uint8_t>(0x81);
    _M_len[1] = static_cast<uint8_t>(len);

    _M_lenlen = 2;
  } else if (len <= 0xffffull) {
    _M_len[0] = static_cast<uint8_t>(0x82);
    _M_len[1] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[2] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 3;
  } else if (len <= 0xffffffull) {
    _M_len[0] = static_cast<uint8_t>(0x83);
    _M_len[1] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[3] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 4;
  } else if (len <= 0xffffffffull) {
    _M_len[0] = static_cast<uint8_t>(0x84);
    _M_len[1] = static_cast<uint8_t>((len >> 24) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[3] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[4] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 5;
  } else if (len <= 0xffffffffffull) {
    _M_len[0] = static_cast<uint8_t>(0x85);
    _M_len[1] = static_cast<uint8_t>((len >> 32) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 24) & 0xff);
    _M_len[3] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[4] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[5] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 6;
  } else if (len <= 0xffffffffffffull) {
    _M_len[0] = static_cast<uint8_t>(0x86);
    _M_len[1] = static_cast<uint8_t>((len >> 40) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 32) & 0xff);
    _M_len[3] = static_cast<uint8_t>((len >> 24) & 0xff);
    _M_len[4] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[5] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[6] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 7;
  } else if (len <= 0xffffffffffffffull) {
    _M_len[0] = static_cast<uint8_t>(0x87);
    _M_len[1] = static_cast<uint8_t>((len >> 48) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 40) & 0xff);
    _M_len[3] = static_cast<uint8_t>((len >> 32) & 0xff);
    _M_len[4] = static_cast<uint8_t>((len >> 24) & 0xff);
    _M_len[5] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[6] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[7] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 8;
  } else {
    _M_len[0] = static_cast<uint8_t>(0x88);
    _M_len[1] = static_cast<uint8_t>((len >> 56) & 0xff);
    _M_len[2] = static_cast<uint8_t>((len >> 48) & 0xff);
    _M_len[3] = static_cast<uint8_t>((len >> 40) & 0xff);
    _M_len[4] = static_cast<uint8_t>((len >> 32) & 0xff);
    _M_len[5] = static_cast<uint8_t>((len >> 24) & 0xff);
    _M_len[6] = static_cast<uint8_t>((len >> 16) & 0xff);
    _M_len[7] = static_cast<uint8_t>((len >> 8) & 0xff);
    _M_len[8] = static_cast<uint8_t>(len & 0xff);

    _M_lenlen = 9;
  }

  // Save value length.
  _M_valuelen = len;
}
