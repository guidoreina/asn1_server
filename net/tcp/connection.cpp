#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include "net/tcp/connection.h"

net::tcp::connection::~connection()
{
  if (_M_fd != -1) {
    ::close(_M_fd);
  }
}

void net::tcp::connection::init(int fd,
                                const struct sockaddr_storage& addr,
                                socklen_t addrlen)
{
  // Save socket descriptor.
  _M_fd = fd;

  // Socket is not readable.
  _M_readable = false;

  // IPv4 address?
  if (addr.ss_family == AF_INET) {
    const struct sockaddr_in* const
      sin = reinterpret_cast<const struct sockaddr_in*>(&addr);

    inet_ntop(AF_INET, &sin->sin_addr, _M_address, sizeof(_M_address));
    _M_port = ntohs(sin->sin_port);
  } else {
    const struct sockaddr_in6* const
      sin = reinterpret_cast<const struct sockaddr_in6*>(&addr);

    inet_ntop(AF_INET6, &sin->sin6_addr, _M_address, sizeof(_M_address));
    _M_port = ntohs(sin->sin6_port);
  }

  // Clear buffer.
  _M_buf.clear();
}

void net::tcp::connection::close()
{
  ::close(_M_fd);
  _M_fd = -1;
}

bool net::tcp::connection::read()
{
  static constexpr const size_t buffer_size = 32 * 1024;

  // Reserve memory for reading.
  if (_M_buf.reserve(buffer_size)) {
    // Make `buf` point at the end of the buffer.
    uint8_t* const
      buf = static_cast<uint8_t*>(const_cast<void*>(_M_buf.data())) +
            _M_buf.length();

    // Get remaining space available in the buffer.
    const size_t remaining = _M_buf.remaining();

    do {
      // Receive.
      const ssize_t ret = ::recv(_M_fd, buf, remaining, 0);

      switch (ret) {
        default:
          // Resize buffer.
          if (_M_buf.resize(_M_buf.length() + ret)) {
            // If we have exhausted the read I/O space...
            if (static_cast<size_t>(ret) < remaining) {
              _M_readable = false;
            }

            return true;
          } else {
            return false;
          }

          break;
        case 0:
          // Connection closed by peer.
          return false;
        case -1:
          if (errno == EAGAIN) {
            _M_readable = false;
            return true;
          } else if (errno != EINTR) {
            return false;
          }

          break;
      }
    } while (true);
  }

  return false;
}
