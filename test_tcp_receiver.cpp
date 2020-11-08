#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <inttypes.h>
#include "net/tcp/receiver.h"

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
                            net::tcp::receiver& receiver);

static bool new_connection(net::tcp::connection* conn,
                           size_t nworker,
                           void* user);

static bool data_received(const void* data,
                          size_t len,
                          net::tcp::connection* conn,
                          size_t nworker,
                          void* user);

static void connection_closed(net::tcp::connection* conn,
                              size_t nworker,
                              void* user);

int main(int argc, const char* argv[])
{
  // Parse number of workers.
  size_t nworkers;
  if (parse_number_workers(argc, argv, nworkers)) {
    net::tcp::receiver receiver(nworkers);

    // Parse arguments.
    if (parse_arguments(argc, argv, receiver)) {
      // Block signals SIGINT and SIGTERM.
      sigset_t set;
      sigemptyset(&set);
      sigaddset(&set, SIGINT);
      sigaddset(&set, SIGTERM);
      if (pthread_sigmask(SIG_BLOCK, &set, nullptr) == 0) {
        net::tcp::connection::callbacks callbacks(new_connection,
                                                  data_received,
                                                  connection_closed);

        // Start receiver.
        if (receiver.start(callbacks)) {
          printf("Waiting for signal to arrive.\n");

          // Wait for signal to arrive.
          int sig;
          while (sigwait(&set, &sig) != 0);

          printf("Signal received.\n");

          receiver.stop();

          return 0;
        } else {
          fprintf(stderr, "Error starting receiver.\n");
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
          "[--number-workers <number-workers>]\n",
          program);

  fprintf(stderr, "<ip-port> ::= <ip-address>:<port>\n");
  fprintf(stderr, "<ip-address> ::= <ipv4-address> | <ipv6-address>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Minimum number of workers: 1.\n");

  fprintf(stderr,
          "Maximum number of workers: %zu.\n",
          net::tcp::receiver::max_workers);

  fprintf(stderr,
          "Default number of workers: %zu.\n",
          net::tcp::receiver::default_workers);

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

bool parse_arguments(int argc, const char* argv[], net::tcp::receiver& receiver)
{
  size_t nbind = 0;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--bind") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // Listen.
        if (receiver.listen(argv[i + 1])) {
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
    } else if (strcasecmp(argv[i], "--number-workers") == 0) {
      i += 2;
    } else {
      fprintf(stderr, "Invalid argument '%s'.\n", argv[i]);
      return false;
    }
  }

  if (argc > 1) {
    if (nbind > 0) {
      return true;
    } else {
      fprintf(stderr, "At least one bind address has to be specified.\n");
    }
  } else {
    usage(argv[0]);
  }

  return false;
}

bool new_connection(net::tcp::connection* conn, size_t nworker, void* user)
{
  printf("[thread-%zu] New connection from [%s]:%u.\n",
         nworker,
         conn->address(),
         conn->port());

  return true;
}

bool data_received(const void* data,
                   size_t len,
                   net::tcp::connection* conn,
                   size_t nworker,
                   void* user)
{
  printf("[thread-%zu] Received %zu byte%s from [%s]:%u:\n",
         nworker,
         len,
         (len != 1) ? "s" : "",
         conn->address(),
         conn->port());

  printf("%.*s\n", static_cast<int>(len), static_cast<const char*>(data));

  printf("--------------------------\n");

  // Clear buffer.
  conn->buffer().clear();

  return true;
}

void connection_closed(net::tcp::connection* conn, size_t nworker, void* user)
{
  printf("[thread-%zu] Connection closed to [%s]:%u.\n",
         nworker,
         conn->address(),
         conn->port());
}
