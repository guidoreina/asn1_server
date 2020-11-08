#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <inttypes.h>
#include "asn1/ber/server.h"

static void usage(const char* program);
static bool parse_number_workers(int argc,
                                 const char* argv[],
                                 size_t& nworkers);

static bool parse_number(const char* s,
                         size_t len,
                         const char* name,
                         uint64_t& n,
                         uint64_t min = 0,
                         uint64_t max = ULLONG_MAX);

static bool parse_arguments(int argc,
                            const char* argv[],
                            const char*& tempdir,
                            const char*& finaldir,
                            size_t& maxfilesize,
                            time_t& maxfileage,
                            asn1::ber::server& server);

int main(int argc, const char* argv[])
{
  // Parse number of workers.
  size_t nworkers;
  if (parse_number_workers(argc, argv, nworkers)) {
    asn1::ber::server server(nworkers);

    const char* tempdir;
    const char* finaldir;
    size_t maxfilesize;
    time_t maxfileage;

    // Parse arguments.
    if (parse_arguments(argc,
                        argv,
                        tempdir,
                        finaldir,
                        maxfilesize,
                        maxfileage,
                        server)) {
      // Block signals SIGINT and SIGTERM.
      sigset_t set;
      sigemptyset(&set);
      sigaddset(&set, SIGINT);
      sigaddset(&set, SIGTERM);
      if (pthread_sigmask(SIG_BLOCK, &set, nullptr) == 0) {
        // Start server.
        if (server.start(tempdir, finaldir, maxfilesize, maxfileage)) {
          printf("Waiting for signal to arrive.\n");

          // Wait for signal to arrive.
          int sig;
          while (sigwait(&set, &sig) != 0);

          printf("Signal received.\n");

          server.stop();

          return 0;
        } else {
          fprintf(stderr, "Error starting server.\n");
        }
      } else {
        fprintf(stderr, "Error blocking signals.\n");
      }
    }
  }

  return -1;
}

void usage(const char* program)
{
  fprintf(stderr,
          "Usage: %s "
          "[--bind <ip-port>]+ "
          "[--number-workers <number-workers>] "
          "--temp-dir <directory> "
          "--final-dir <directory> "
          "--max-file-size <size> "
          "--max-file-age <seconds>\n",
          program);

  fprintf(stderr, "<ip-port> ::= <ip-address>:<port>\n");
  fprintf(stderr, "<ip-address> ::= <ipv4-address> | <ipv6-address>\n");
  fprintf(stderr, "\n");
  fprintf(stderr,
          "Number of workers: 1 .. %zu, default: %zu.\n",
          net::tcp::receiver::max_workers,
          net::tcp::receiver::default_workers);

  fprintf(stderr,
          "File size: %zu .. %zu.\n",
          asn1::ber::server::min_file_size,
          asn1::ber::server::max_file_size);

  fprintf(stderr,
          "File age: %ld .. %ld (seconds).\n",
          asn1::ber::server::min_file_age,
          asn1::ber::server::max_file_age);

  fprintf(stderr, "\n");
}

bool parse_number_workers(int argc, const char* argv[], size_t& nworkers)
{
  nworkers = net::tcp::receiver::default_workers;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--number-workers") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // Parse number of workers.
        uint64_t n;
        if (parse_number(argv[i + 1],
                         strlen(argv[i + 1]),
                         "number of workers",
                         n,
                         1,
                         net::tcp::receiver::max_workers)) {
          nworkers = static_cast<size_t>(n);
          return true;
        } else {
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected number of workers after \"--number-workers\".\n");

        return false;
      }
    }

    i++;
  }

  return true;
}

bool parse_number(const char* s,
                  size_t len,
                  const char* name,
                  uint64_t& n,
                  uint64_t min,
                  uint64_t max)
{
  // If the string is not empty...
  if (len > 0) {
    uint64_t res = 0;

    for (size_t i = 0; i < len; i++) {
      // Digit?
      if ((s[i] >= '0') && (s[i] <= '9')) {
        const uint64_t tmp = (res * 10) + (s[i] - '0');

        // If the number doesn't overflow...
        if (tmp >= res) {
          // If the number is not too big...
          if (tmp <= max) {
            res = tmp;
          } else {
            fprintf(stderr,
                    "The %s '%.*s' is too big (maximum: %" PRIu64 ").\n",
                    name,
                    static_cast<int>(len),
                    s,
                    max);

            return false;
          }
        } else {
          fprintf(stderr,
                  "Invalid %s '%.*s' (overflow).\n",
                  name,
                  static_cast<int>(len),
                  s);

          return false;
        }
      } else {
        fprintf(stderr,
                "Invalid %s '%.*s' (not a number).\n",
                name,
                static_cast<int>(len),
                s);

        return false;
      }
    }

    // If the number is not too small...
    if (res >= min) {
      n = res;
      return true;
    } else {
      fprintf(stderr,
              "The %s '%.*s' is too small (minimum: %" PRIu64 ").\n",
              name,
              static_cast<int>(len),
              s,
              min);
    }
  } else {
    fprintf(stderr, "The %s is empty.\n", name);
  }

  return false;
}

bool parse_arguments(int argc,
                     const char* argv[],
                     const char*& tempdir,
                     const char*& finaldir,
                     size_t& maxfilesize,
                     time_t& maxfileage,
                     asn1::ber::server& server)
{
  tempdir = nullptr;
  finaldir = nullptr;
  maxfilesize = 0;
  maxfileage = 0;
  size_t nbind = 0;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--bind") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // Listen.
        if (server.listen(argv[i + 1])) {
          // Increment number of bind addresses.
          nbind++;

          i += 2;
        } else {
          fprintf(stderr, "Error listening on '%s'.\n", argv[i + 1]);
          return false;
        }
      } else {
        fprintf(stderr, "Expected IP address and port after \"--bind\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--temp-dir") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        tempdir = argv[i + 1];

        i += 2;
      } else {
        fprintf(stderr, "Expected temporary directory after \"--temp-dir\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--final-dir") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        finaldir = argv[i + 1];

        i += 2;
      } else {
        fprintf(stderr, "Expected final directory after \"--final-dir\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--max-file-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // Parse maximum file size.
        uint64_t n;
        if (parse_number(argv[i + 1],
                         strlen(argv[i + 1]),
                         "maximum file size",
                         n,
                         asn1::ber::server::min_file_size,
                         asn1::ber::server::max_file_size)) {
          maxfilesize = static_cast<size_t>(n);

          i += 2;
        } else {
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected maximum file size after \"--max-file-size\".\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--max-file-age") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // Parse maximum file age.
        uint64_t n;
        if (parse_number(argv[i + 1],
                         strlen(argv[i + 1]),
                         "maximum file age",
                         n,
                         asn1::ber::server::min_file_age,
                         asn1::ber::server::max_file_age)) {
          maxfileage = static_cast<time_t>(n);

          i += 2;
        } else {
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected maximum file age after \"--max-file-age\".\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--number-workers") == 0) {
      i += 2;
    } else {
      fprintf(stderr, "Invalid argument '%s'.\n", argv[i]);
      return false;
    }
  }

  if (argc > 1) {
    if ((nbind > 0) &&
        (tempdir) &&
        (finaldir) &&
        (maxfilesize != 0) &&
        (maxfileage != 0)) {
      return true;
    } else if (nbind == 0) {
      fprintf(stderr, "At least one bind address has to be specified.\n");
    } else if (!tempdir) {
      fprintf(stderr, "Temporary directory has not been specified.\n");
    } else if (!finaldir) {
      fprintf(stderr, "Final directory has not been specified.\n");
    } else if (maxfilesize == 0) {
      fprintf(stderr, "Maximum file size has not been specified.\n");
    } else {
      fprintf(stderr, "Maximum file age has not been specified.\n");
    }
  } else {
    usage(argv[0]);
  }

  return false;
}
