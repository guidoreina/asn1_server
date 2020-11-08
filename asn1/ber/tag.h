#ifndef ASN1_BER_TAG_H
#define ASN1_BER_TAG_H

#include <stdint.h>

namespace asn1 {
  namespace ber {
    // Tag class.
    enum class tag_class : uint8_t {
      Universal       = 0,
      Application     = 1,
      ContextSpecific = 2,
      Private         = 3
    };

    // Value type.
    enum class type : uint32_t {
      EnfOfContents    = 0,
      Boolean          = 1,
      Integer          = 2,
      Bitstring        = 3,
      Octetstring      = 4,
      Null             = 5,
      ObjectIdentifier = 6,
      ObjectDescriptor = 7,
      External         = 8,
      Real             = 9,
      Enumerated       = 10,
      EmbeddedPdv      = 11,
      UTF8String       = 12,
      RelativeOID      = 13,
      Time             = 14,
      Sequence         = 16,
      Set              = 17,
      NumericString    = 18,
      PrintableString  = 19,
      TeletexString    = 20,
      VideotexString   = 21,
      IA5String        = 22,
      UTCTime          = 23,
      GeneralizedTime  = 24,
      GraphicString    = 25,
      VisibleString    = 26,
      GeneralString    = 27,
      UniversalString  = 28,
      CharacterString  = 29,
      BMPString        = 30
    };

    const char* to_string(tag_class tc);
    const char* to_string(type t);
  }
}

#endif // ASN1_BER_TAG_H
