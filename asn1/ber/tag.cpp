#include "asn1/ber/tag.h"

const char* asn1::ber::to_string(tag_class tc)
{
  switch (tc) {
    case tag_class::Universal:       return "Universal";
    case tag_class::Application:     return "Application";
    case tag_class::ContextSpecific: return "Context-specific";
    case tag_class::Private:         return "Private";
    default:                         return "(unknown-class)";
  }
}

const char* asn1::ber::to_string(type t)
{
  switch (t) {
    case type::EnfOfContents:    return "end-of-contents";
    case type::Boolean:          return "boolean";
    case type::Integer:          return "integer";
    case type::Bitstring:        return "bitstring";
    case type::Octetstring:      return "octetstring";
    case type::Null:             return "Null";
    case type::ObjectIdentifier: return "object identifier";
    case type::ObjectDescriptor: return "object descriptor";
    case type::External:         return "external";
    case type::Real:             return "real";
    case type::Enumerated:       return "enumerated";
    case type::EmbeddedPdv:      return "embedded-pdv";
    case type::UTF8String:       return "UTF8String";
    case type::RelativeOID:      return "relative OID";
    case type::Time:             return "time";
    case type::Sequence:         return "sequence";
    case type::Set:              return "set";
    case type::NumericString:    return "NumericString";
    case type::PrintableString:  return "PrintableString";
    case type::TeletexString:    return "TeletexString";
    case type::VideotexString:   return "VideotexString";
    case type::IA5String:        return "IA5String";
    case type::UTCTime:          return "UTCTime";
    case type::GeneralizedTime:  return "GeneralizedTime";
    case type::GraphicString:    return "GraphicString";
    case type::VisibleString:    return "VisibleString";
    case type::GeneralString:    return "GeneralString";
    case type::UniversalString:  return "UniversalString";
    case type::CharacterString:  return "character string";
    case type::BMPString:        return "BMPString";
    default:                     return "(unknown-type)";
  }
}
