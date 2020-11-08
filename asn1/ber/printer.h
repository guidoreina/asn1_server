#ifndef ASN1_BER_PRINTER_H
#define ASN1_BER_PRINTER_H

#include "asn1/ber/decoder.h"

namespace asn1 {
  namespace ber {
    // ASN.1 BER printer.
    class printer {
      public:
        // Constructor.
        printer(size_t tab_size = default_tab_size);
        printer(const printer&) = default;

        // Destructor.
        ~printer() = default;

        // Assignment operator.
        printer& operator=(const printer&) = default;

        // Print.
        bool print(size_t offset, const void* data, size_t& len);
        bool print(size_t offset, decoder& decoder, size_t& len);

        // End of file?
        bool eof() const;

      private:
        // Default tab size.
        static constexpr const size_t default_tab_size = 2;

        // Maximum number of hexadecimal characters per line.
        static constexpr const size_t number_hex_chars_per_line = 16;

        // Maximum number of ASCII characters per line.
        static constexpr const size_t
          number_ascii_chars_per_line = (number_hex_chars_per_line * 3) - 1;

        // Tab size.
        const size_t _M_tab_size;

        // End of file?
        bool _M_eof = false;

        // Enter constructed.
        void enter_constructed(decoder& decoder, size_t depth) const;

        // Leave constructed.
        void leave_constructed(decoder& decoder, size_t depth) const;

        // Print.
        bool print(decoder& decoder, size_t depth) const;

        // Print primitive.
        bool print_primitive(const value& value, size_t depth) const;

        // Print constructed.
        void print_constructed(const value& value, size_t depth) const;

        // Print in ASCII.
        void print_ascii(const value& value, size_t depth) const;

        // Print in hexadecimal.
        void print_hexadecimal(const value& value, size_t depth) const;

        void print_boolean(bool val, size_t depth) const;
        void print_integer(int64_t val, size_t depth) const;
        void print_oid(const uint32_t* val,
                       size_t ncomponents,
                       size_t depth) const;

        void print_utc_time(time_t val, size_t depth) const;
        void print_generalized_time(const struct timeval& val,
                                    size_t depth) const;

        void indent(size_t depth) const;

        // Print header.
        static void print_header(size_t offset);

        // Print footer.
        static void print_footer();
    };

    inline printer::printer(size_t tab_size)
      : _M_tab_size(tab_size)
    {
    }

    inline bool printer::eof() const
    {
      return _M_eof;
    }
  }
}

#endif // ASN1_BER_PRINTER_H
