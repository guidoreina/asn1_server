#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#if !defined(_WIN32)
  #include <unistd.h>
  #include <sys/mman.h>
#else
  #include <windows.h>
#endif

#include "asn1/ber/printer.h"

static int process_file(const char* filename);
static int process_data(const uint8_t* data, size_t len);

int main(int argc, const char* argv[])
{
  if (argc == 2) {
    // Process file.
    return process_file(argv[1]);
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return EXIT_FAILURE;
}

#if !defined(_WIN32)
int process_file(const char* filename)
{
  // If the file exists and is a regular file...
  struct stat sbuf;
  if ((stat(filename, &sbuf) == 0) && (S_ISREG(sbuf.st_mode))) {
    // Open file for reading.
    const int fd = open(filename, O_RDONLY);

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
        // Process data.
        const int ret = process_data(static_cast<const uint8_t*>(base),
                                     static_cast<size_t>(sbuf.st_size));

        munmap(base, sbuf.st_size);

        close(fd);

        return ret;
      } else {
        fprintf(stderr, "Error mapping file '%s' into memory.\n", filename);

        close(fd);
      }
    } else {
      fprintf(stderr, "Error opening file '%s' for reading.\n", filename);
    }
  } else {
    fprintf(stderr,
            "'%s' doesn't exist or is not a regular file.\n",
            filename);
  }

  return EXIT_FAILURE;
}
#else
int process_file(const char* filename)
{
  // If the file exists and is a regular file...
  struct _stat64 sbuf;
  if ((_stat64(filename, &sbuf) == 0) && ((sbuf.st_mode & _S_IFREG) != 0)) {
    // Open file for reading.
    const HANDLE hFile = CreateFile(filename,
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);

    // If the file could be opened...
    if (hFile != INVALID_HANDLE_VALUE) {
      // Create file mapping.
      const HANDLE hMapFile = CreateFileMapping(hFile,
                                                nullptr,
                                                PAGE_READONLY,
                                                0,
                                                0,
                                                nullptr);

      // If the file mapping could be created...
      if (hMapFile) {
        // Map a view of the file mapping into the address space of the process.
        void* const base = MapViewOfFile(hMapFile,
                                         FILE_MAP_READ,
                                         0,
                                         0,
                                         0);

        // If the view of the file mapping could be mapped into the address
        // space of the process...
        if (base) {
          // Process data.
          const int ret = process_data(static_cast<const uint8_t*>(base),
                                       static_cast<size_t>(sbuf.st_size));

          UnmapViewOfFile(base);
          CloseHandle(hMapFile);
          CloseHandle(hFile);

          return ret;
        } else {
          fprintf(stderr,
                  "Error mapping a view of the file mapping into the address "
                  "space of the process.\n");

          CloseHandle(hMapFile);
        }
      } else {
        fprintf(stderr, "Error creating file mapping.\n");
      }

      CloseHandle(hFile);
    } else {
      fprintf(stderr, "Error opening file '%s' for reading.\n", filename);
    }
  } else {
    fprintf(stderr,
            "'%s' doesn't exist or is not a regular file.\n",
            filename);
  }

  return EXIT_FAILURE;
}
#endif

int process_data(const uint8_t* data, size_t len)
{
  size_t offset = 0;

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
        return EXIT_SUCCESS;
      } else {
        fprintf(stderr,
                "Error decoding ASN.1 data (offset: %zu).\n",
                offset);

        return EXIT_FAILURE;
      }
    }
  } while (true);
}
