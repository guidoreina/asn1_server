#include <stdlib.h>
#include <stdio.h>
#include "asn1/ber/encoder.h"

int main()
{
  asn1::ber::encoder encoder;

  if ((encoder.start_constructed(asn1::ber::tag_class::ContextSpecific, 0)) &&
      (encoder.add_integer(asn1::ber::tag_class::ContextSpecific, 1, 314)) &&
      (encoder.add_integer(asn1::ber::tag_class::ContextSpecific, 2, 315)) &&
      (encoder.start_constructed(asn1::ber::tag_class::ContextSpecific, 3)) &&
      (encoder.add_integer(asn1::ber::tag_class::ContextSpecific, 4, 316)) &&
      (encoder.end_constructed()) &&
      (encoder.start_constructed(asn1::ber::tag_class::ContextSpecific, 5)) &&
      (encoder.add_integer(asn1::ber::tag_class::ContextSpecific, 6, 316)) &&
      (encoder.add_data(asn1::ber::tag_class::ContextSpecific,
                        7,
                        "Testtest",
                        8,
                        asn1::ber::encoder::copy::shallow)) &&
      (encoder.start_constructed(asn1::ber::tag_class::ContextSpecific, 8)) &&
      (encoder.add_data(asn1::ber::tag_class::ContextSpecific,
                        9,
                        "AAAA",
                        4,
                        asn1::ber::encoder::copy::shallow)) &&
      (encoder.add_generalized_time(asn1::ber::tag_class::ContextSpecific,
                                    10)) &&
      (encoder.end_constructed()) &&
      (encoder.end_constructed()) &&
      (encoder.end_constructed()) &&
      (encoder.serialize("test.asn1"))) {
    printf("Success.\n");
    return 0;
  }

  fprintf(stderr, "Error.\n");

  return -1;
}
