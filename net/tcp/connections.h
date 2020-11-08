#ifndef NET_TCP_CONNECTIONS_H
#define NET_TCP_CONNECTIONS_H

namespace net {
  namespace tcp {
    // Forward declaration.
    class connection;

    // TCP connections.
    class connections {
      public:
        // Maximum number of connections.
        static constexpr const size_t max_connections = 256;

        // Constructor.
        connections() = default;

        // Destructor.
        ~connections();

        // Get new connection.
        connection* pop();

        // Return connection.
        void push(connection* conn);

      private:
        // Allocation.
        static constexpr const size_t allocation = 32;

        // Connections.
        connection* _M_connections = nullptr;

        // Free connections.
        connection* _M_free = nullptr;

        // Number of connections in use.
        size_t _M_nconnections = 0;

        // Erase connection list.
        static void erase(const connection* conn);

        // Allocate.
        bool allocate();

        // Disable copy constructor and assignment operator.
        connections(const connections&) = delete;
        connections& operator=(const connections&) = delete;
    };
  }
}

#endif // NET_TCP_CONNECTIONS_H
