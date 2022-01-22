#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include "asn1/ber/printer.h"

bool asn1::ber::printer::print(size_t offset, const void* data, size_t& len)
{
  decoder decoder(data, len);
  return print(offset, decoder, len);
}

bool asn1::ber::printer::print(size_t offset, decoder& decoder, size_t& len)
{
  // Get data value.
  value val;
  switch (decoder.next(val)) {
    case decoder::result::no_error:
      // Print header.
      print_header(offset);

      // Constructed?
      if (val.constructed()) {
        // Print constructed.
        print_constructed(val, 0);

        // Enter constructed.
        enter_constructed(decoder, 0);

        // Print child data values.
        if (print(decoder, 1)) {
          // Leave constructed.
          leave_constructed(decoder, 0);

          // Print footer.
          print_footer();

          // Save total length of the data value.
          len = val.total_length();

          return true;
        }
      } else {
        // Print primitive.
        if (print_primitive(val, 0)) {
          // Print footer.
          print_footer();

          // Save total length of the data value.
          len = val.total_length();

          return true;
        }
      }

      break;
    case decoder::result::eof:
      _M_eof = true;
      break;
    default:
      break;
  }

  return false;
}

void asn1::ber::printer::enter_constructed(decoder& decoder, size_t depth) const
{
  // Enter constructed.
  decoder.enter_constructed();

  indent(depth);
  printf("{\n");
}

void asn1::ber::printer::leave_constructed(decoder& decoder, size_t depth) const
{
  // Leave constructed.
  decoder.leave_constructed();

  indent(depth);
  printf("}\n");
}

bool asn1::ber::printer::print(decoder& decoder, size_t depth) const
{
  do {
    // Get next data value.
    value val;
    switch (decoder.next(val)) {
      case decoder::result::no_error:
        // Primitive?
        if (val.primitive()) {
          // Print primitive.
          if (!print_primitive(val, depth)) {
            return false;
          }
        } else {
          // Print constructed.
          print_constructed(val, depth);

          // Enter constructed.
          enter_constructed(decoder, depth);

          // Print child data values.
          if (print(decoder, depth + 1)) {
            // Leave constructed.
            leave_constructed(decoder, depth);
          } else {
            return false;
          }
        }

        break;
      case decoder::result::eof:
        return true;
      default:
        return false;
    }
  } while (true);
}

bool asn1::ber::printer::print_primitive(const value& value, size_t depth) const
{
  indent(depth);

  // Universal?
  if (value.tag_class() == tag_class::Universal) {
    printf("[Primitive] Tag class: %s, tag: %s, length: %zu, total length: "
           "%zu\n",
           to_string(value.tag_class()),
           to_string(static_cast<type>(value.tag_number())),
           value.length(),
           value.total_length());

    switch (value.tag_number()) {
      case static_cast<uint32_t>(type::Boolean):
        {
          // Decode boolean.
          bool val;
          if (value.decode_boolean(val)) {
            print_boolean(val, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      case static_cast<uint32_t>(type::Integer):
        {
          // Decode integer.
          int64_t val;
          if (value.decode_integer(val)) {
            print_integer(val, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      case static_cast<uint32_t>(type::Null):
        // Decode null.
        if (!value.decode_null()) {
          fprintf(stderr,
                  "Error decoding '%s'.\n",
                  to_string(static_cast<type>(value.tag_number())));

          return false;
        }

        break;
      case static_cast<uint32_t>(type::ObjectIdentifier):
        {
          // Decode OID.
          uint32_t val[value::max_oid_components];
          size_t ncomponents;
          if (value.decode_oid(val, ncomponents)) {
            print_oid(val, ncomponents, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      case static_cast<uint32_t>(type::Enumerated):
        {
          // Decode enumerated.
          int64_t val;
          if (value.decode_enumerated(val)) {
            print_integer(val, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      case static_cast<uint32_t>(type::UTCTime):
        {
          // Decode UTCTime.
          time_t val;
          if (value.decode_utc_time(val)) {
            print_utc_time(val, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      case static_cast<uint32_t>(type::GeneralizedTime):
        {
          // Decode GeneralizedTime.
          struct timeval val;
          if (value.decode_generalized_time(val)) {
            print_generalized_time(val, depth);
          } else {
            fprintf(stderr,
                    "Error decoding '%s'.\n",
                    to_string(static_cast<type>(value.tag_number())));

            return false;
          }
        }

        break;
      default:
        print_ascii(value, depth);
        break;
    }
  } else {
    printf("[Primitive] Tag class: %s, tag number: %u, length: %zu, total "
           "length: %zu\n",
           to_string(value.tag_class()),
           value.tag_number(),
           value.length(),
           value.total_length());

    print_ascii(value, depth);
  }

  print_hexadecimal(value, depth);

  return true;
}

void asn1::ber::printer::print_constructed(const value& value,
                                           size_t depth) const
{
  indent(depth);

  if (value.tag_class() == tag_class::Universal) {
    printf("%s: %s, length: %zu, total length: %zu\n",
           to_string(value.tag_class()),
           to_string(static_cast<type>(value.tag_number())),
           value.length(),
           value.total_length());
  } else {
    printf("%s: %u, length: %zu, total length: %zu\n",
           to_string(value.tag_class()),
           value.tag_number(),
           value.length(),
           value.total_length());
  }
}

void asn1::ber::printer::print_ascii(const value& value, size_t depth) const
{
  indent(depth);
  printf("  Value:");

  const uint8_t* const data = static_cast<const uint8_t*>(value.data());

  for (size_t i = 0; i < value.length(); i++) {
    if ((i % number_ascii_chars_per_line) == 0) {
      printf("\n");
      indent(depth);
      printf("    ");
    }

    printf("%c", isprint(data[i]) ? static_cast<char>(data[i]) : '.');
  }

  printf("\n\n");
}

void asn1::ber::printer::print_hexadecimal(const value& value,
                                           size_t depth) const
{
  indent(depth);
  printf("  Hexadecimal:");

  const uint8_t* const data = static_cast<const uint8_t*>(value.data());

  for (size_t i = 0; i < value.length(); i++) {
    if ((i % number_hex_chars_per_line) == 0) {
      printf("\n");
      indent(depth);
      printf("   ");
    }

    printf(" %02x", data[i]);
  }

  printf("\n");
}

void asn1::ber::printer::print_boolean(bool val, size_t depth) const
{
  indent(depth);
  printf("  Value:\n");

  indent(depth);
  printf("    %s\n\n", val ? "true" : "false");
}

void asn1::ber::printer::print_integer(int64_t val, size_t depth) const
{
  indent(depth);
  printf("  Value:\n");

  indent(depth);
  printf("    %" PRId64 "\n\n", val);
}

void asn1::ber::printer::print_oid(const uint32_t* val,
                                   size_t ncomponents,
                                   size_t depth) const
{
  indent(depth);
  printf("  Value:\n");

  indent(depth);
  printf("    ");

  for (size_t i = 0; i < ncomponents; i++) {
    printf("%s%u", (i > 0) ? "." : "", val[i]);
  }

  printf("\n\n");
}

void asn1::ber::printer::print_utc_time(time_t val, size_t depth) const
{
  indent(depth);
  printf("  Value:\n");

  indent(depth);

#if !defined(_WIN32)
  struct tm tm;
  gmtime_r(&val, &tm);
  const struct tm* const tmp = &tm;
#else
  const struct tm* const tmp = gmtime(&val);
#endif

  printf("    %04u/%02u/%02u %02u:%02u:%02u (UTC)\n\n",
         1900 + tmp->tm_year,
         1 + tmp->tm_mon,
         tmp->tm_mday,
         tmp->tm_hour,
         tmp->tm_min,
         tmp->tm_sec);
}

void asn1::ber::printer::print_generalized_time(const struct timeval& val,
                                                size_t depth) const
{
  indent(depth);
  printf("  Value:\n");

  indent(depth);

#if !defined(_WIN32)
  struct tm tm;
  gmtime_r(&val.tv_sec, &tm);
  const struct tm* const tmp = &tm;
#else
  const time_t t = val.tv_sec;
  const struct tm* const tmp = gmtime(&t);
#endif

  if (val.tv_usec != 0) {
    printf("    %04u/%02u/%02u %02u:%02u:%02u.%06u (UTC)\n\n",
           1900 + tmp->tm_year,
           1 + tmp->tm_mon,
           tmp->tm_mday,
           tmp->tm_hour,
           tmp->tm_min,
           tmp->tm_sec,
           static_cast<unsigned>(val.tv_usec));
  } else {
    printf("    %04u/%02u/%02u %02u:%02u:%02u (UTC)\n\n",
           1900 + tmp->tm_year,
           1 + tmp->tm_mon,
           tmp->tm_mday,
           tmp->tm_hour,
           tmp->tm_min,
           tmp->tm_sec);
  }
}

void asn1::ber::printer::indent(size_t depth) const
{
  for (size_t i = depth * _M_tab_size; i > 0; i--) {
    printf(" ");
  }
}

void asn1::ber::printer::print_header(size_t offset)
{
  printf("Offset: %zu\n", offset);
  printf("---------------------------------------------------------------------"
         "-----------\n");
}

void asn1::ber::printer::print_footer()
{
  printf("====================================================================="
         "===========\n");
}
