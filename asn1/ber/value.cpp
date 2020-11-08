#include "asn1/ber/value.h"

#define IS_DIGIT(x) (((x) >= '0') && ((x) <= '9'))

bool asn1::ber::value::decode_boolean(bool& val) const
{
  if ((_M_primitive) && (_M_length == 1)) {
    val = *_M_data != 0;
    return true;
  }

  return false;
}

bool asn1::ber::value::decode_integer(int64_t& val) const
{
  if ((_M_primitive) && (_M_length >= 1) && (_M_length <= 8)) {
    uint64_t n = 0;
    for (size_t i = 0; i < _M_length; i++) {
      n = (n << 8) | _M_data[i];
    }

    // If the number is positive...
    if ((_M_data[0] & 0x80u) == 0) {
      val = static_cast<int64_t>(n);
    } else {
      // `n` is in two's complement.
      n |= (~static_cast<uint64_t>(0) << (_M_length << 3));

      val = -static_cast<int64_t>(~n + 1);
    }

    return true;
  }

  return false;
}

bool asn1::ber::value::decode_null() const
{
  return ((_M_primitive) && (_M_length == 0));
}

bool asn1::ber::value::decode_oid(uint32_t* components,
                                  size_t& ncomponents) const
{
  if ((_M_primitive) && (_M_length > 0)) {
    components[0] = _M_data[0] / 40;
    components[1] = _M_data[0] % 40;

    size_t count = 2;
    uint32_t component = 0;

    for (size_t i = 1; i < _M_length; i++) {
      // If the component is not too big...
      if (((component >> (32 - 7)) & 0x7fu) == 0) {
        component = (component << 7) | (_M_data[i] & 0x7fu);

        // If this is the last octet...
        if ((_M_data[i] & 0x80u) == 0) {
          // Add component.
          components[count++] = component;

          // If the OID is not too long...
          if (count < max_oid_components) {
            component = 0;
          } else if (i + 1 == _M_length) {
            ncomponents = count;
            return true;
          } else {
            return false;
          }
        }
      } else {
        return false;
      }
    }

    if ((_M_length == 1) || ((_M_data[_M_length - 1] & 0x80u) == 0)) {
      ncomponents = count;
      return true;
    }
  }

  return false;
}

bool asn1::ber::value::decode_utc_time(time_t& val) const
{
  if ((_M_primitive) &&
      (_M_length == 13) &&
      (IS_DIGIT(_M_data[0])) &&
      (IS_DIGIT(_M_data[1])) &&
      (IS_DIGIT(_M_data[2])) &&
      (IS_DIGIT(_M_data[3])) &&
      (IS_DIGIT(_M_data[4])) &&
      (IS_DIGIT(_M_data[5])) &&
      (IS_DIGIT(_M_data[6])) &&
      (IS_DIGIT(_M_data[7])) &&
      (IS_DIGIT(_M_data[8])) &&
      (IS_DIGIT(_M_data[9])) &&
      (IS_DIGIT(_M_data[10])) &&
      (IS_DIGIT(_M_data[11])) &&
      (_M_data[12] == 'Z')) {
    const unsigned year = ((_M_data[0] - '0') * 10) + (_M_data[1] - '0');

    const unsigned month = ((_M_data[2] - '0') * 10) + (_M_data[3] - '0');

    if ((month >= 1) && (month <= 12)) {
      const unsigned mday = ((_M_data[4] - '0') * 10) + (_M_data[5] - '0');

      if ((mday >= 1) && (mday <= 31)) {
        const unsigned hour = ((_M_data[6] - '0') * 10) + (_M_data[7] - '0');

        if (hour <= 23) {
          const unsigned minute = ((_M_data[8] - '0') * 10) +
                                  (_M_data[9] - '0');

          if (minute <= 59) {
            const unsigned second = ((_M_data[10] - '0') * 10) +
                                    (_M_data[11] - '0');

            if (second <= 59) {
              struct tm tm;
              tm.tm_year = (year >= 70) ? year : 100 + year;
              tm.tm_mon = month - 1;
              tm.tm_mday = mday;
              tm.tm_hour = hour;
              tm.tm_min = minute;
              tm.tm_sec = second;
              tm.tm_isdst = -1;

              val = timegm(&tm);

              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

bool asn1::ber::value::decode_generalized_time(struct timeval& val) const
{
  if ((_M_primitive) &&
      (_M_length >= 15) &&
      (_M_length <= 22) &&
      (IS_DIGIT(_M_data[0])) &&
      (IS_DIGIT(_M_data[1])) &&
      (IS_DIGIT(_M_data[2])) &&
      (IS_DIGIT(_M_data[3])) &&
      (IS_DIGIT(_M_data[4])) &&
      (IS_DIGIT(_M_data[5])) &&
      (IS_DIGIT(_M_data[6])) &&
      (IS_DIGIT(_M_data[7])) &&
      (IS_DIGIT(_M_data[8])) &&
      (IS_DIGIT(_M_data[9])) &&
      (IS_DIGIT(_M_data[10])) &&
      (IS_DIGIT(_M_data[11])) &&
      (IS_DIGIT(_M_data[12])) &&
      (IS_DIGIT(_M_data[13])) &&
      (_M_data[_M_length - 1] == 'Z')) {
    const unsigned year = ((_M_data[0] - '0') * 1000) +
                          ((_M_data[1] - '0') * 100) +
                          ((_M_data[2] - '0') * 10) +
                          (_M_data[3] - '0');

    if (year >= 1900) {
      const unsigned month = ((_M_data[4] - '0') * 10) + (_M_data[5] - '0');

      if ((month >= 1) && (month <= 12)) {
        const unsigned mday = ((_M_data[6] - '0') * 10) + (_M_data[7] - '0');

        if ((mday >= 1) && (mday <= 31)) {
          const unsigned hour = ((_M_data[8] - '0') * 10) + (_M_data[9] - '0');

          if (hour <= 23) {
            const unsigned minute = ((_M_data[10] - '0') * 10) +
                                    (_M_data[11] - '0');

            if (minute <= 59) {
              const unsigned second = ((_M_data[12] - '0') * 10) +
                                      (_M_data[13] - '0');

              if (second <= 59) {
                unsigned microsecond = 0;

                if (_M_length > 15) {
                  if ((_M_length >= 17) && (_M_data[14] == '.')) {
                    unsigned n = 1000000;

                    const size_t max = _M_length - 1;
                    for (size_t i = 15; i < max; i++) {
                      if (IS_DIGIT(_M_data[i])) {
                        microsecond = (microsecond * 10) + (_M_data[i] - '0');
                        n /= 10;
                      } else {
                        return false;
                      }
                    }

                    microsecond *= n;
                  } else {
                    return false;
                  }
                }

                struct tm tm;
                tm.tm_year = year - 1900;
                tm.tm_mon = month - 1;
                tm.tm_mday = mday;
                tm.tm_hour = hour;
                tm.tm_min = minute;
                tm.tm_sec = second;
                tm.tm_isdst = -1;

                val.tv_sec = timegm(&tm);
                val.tv_usec = microsecond;

                return true;
              }
            }
          }
        }
      }
    }
  }

  return false;
}
