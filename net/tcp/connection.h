#ifndef NET_TCP_CONNECTION_H
#define NET_TCP_CONNECTION_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "string/buffer.h"

namespace net {
  namespace tcp {
    // Forward declarations.
    class connections;
    class receiver;

    // TCP connection.
    class connection {
      friend class connections;
      friend class receiver;

      public:
        // Callbacks.
        struct callbacks {
          typedef bool (*new_connection_t)(connection*, size_t, void*);
          new_connection_t new_connection = nullptr;

          typedef bool (*data_received_t)(const void*,
                                          size_t,
                                          connection*,
                                          size_t,
                                          void*);

          data_received_t data_received = nullptr;

          typedef void (*connection_closed_t)(connection*, size_t, void*);
          connection_closed_t connection_closed = nullptr;

          void* user = nullptr;

          // Constructors.
          callbacks() = default;
          callbacks(new_connection_t new_connection,
                    data_received_t data_received,
                    connection_closed_t connection_closed,
                    void* user = nullptr);
        };

        // Constructor.
        connection() = default;

        // Destructor.
        ~connection();

        // Get address.
        const char* address() const;

        // Get port.
        in_port_t port() const;

        // Get buffer.
        const string::buffer& buffer() const;
        string::buffer& buffer();

      private:
        // Socket descriptor.
        int _M_fd = -1;

        // Is the socket readable?
        bool _M_readable;

        // Peer address.
        char _M_address[INET6_ADDRSTRLEN];

        // Peer port.
        in_port_t _M_port;

        // Buffer.
        string::buffer _M_buf;

        // Previous connection.
        connection* _M_prev;

        // Next connection.
        connection* _M_next;

        // Initialize.
        void init(int fd,
                  const struct sockaddr_storage& addr,
                  socklen_t addrlen);

        // Close connection.
        void close();

        // Read.
        bool read();

        // Disable copy constructor and assignment operator.
        connection(const connection&) = delete;
        connection& operator=(const connection&) = delete;
    };

    inline
    connection::callbacks::callbacks(new_connection_t new_connection,
                                     data_received_t data_received,
                                     connection_closed_t connection_closed,
                                     void* user)
      : new_connection(new_connection),
        data_received(data_received),
        connection_closed(connection_closed),
        user(user)
    {
    }

    inline const char* connection::address() const
    {
      return _M_address;
    }

    inline in_port_t connection::port() const
    {
      return _M_port;
    }

    inline const string::buffer& connection::buffer() const
    {
      return _M_buf;
    }

    inline string::buffer& connection::buffer()
    {
      return _M_buf;
    }
  }
}

#endif // NET_TCP_CONNECTION_H
