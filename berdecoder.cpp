#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "asn1/ber/printer.h"

int main(int argc, const char* argv[])
{
  if (argc == 2) {
    // If the file exists and is a regular file...
    struct stat sbuf;
    if ((stat(argv[1], &sbuf) == 0) && (S_ISREG(sbuf.st_mode))) {
      // Open file for reading.
      const int fd = open(argv[1], O_RDONLY);

      // If the file could be opened...
      if (fd != -1) {
        // Map file into memory.
        void* const base = mmap(nullptr,
                                sbuf.st_size,
                                PROT_READ,
                                MAP_SHARED,
                                fd,
                                0);

        // If the file could be mapped into memory...
        if (base != MAP_FAILED) {
          const uint8_t* data = static_cast<const uint8_t*>(base);
          size_t len = static_cast<size_t>(sbuf.st_size);

          size_t offset = 0;

          int ret;

          do {
            // Print data value.
            asn1::ber::printer printer;
            size_t l = len;
            if (printer.print(offset, data, l)) {
              data += l;
              len -= l;

              offset += l;
            } else {
              // End of the file?
              if (printer.eof()) {
                ret = 0;
              } else {
                fprintf(stderr,
                        "Error decoding ASN.1 data (offset: %zu).\n",
                        offset);

                ret = -1;
              }

              break;
            }
          } while (true);

          munmap(base, sbuf.st_size);

          close(fd);

          return ret;
        } else {
          fprintf(stderr, "Error mapping file '%s' into memory.\n", argv[1]);

          close(fd);
        }
      } else {
        fprintf(stderr, "Error opening file '%s' for reading.\n", argv[1]);
      }
    } else {
      fprintf(stderr,
              "'%s' doesn't exist or is not a regular file.\n",
              argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}
