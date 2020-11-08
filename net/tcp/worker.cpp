#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "net/tcp/receiver.h"

net::tcp::receiver::worker::~worker()
{
  // Stop worker (if running).
  stop();

  if (_M_epollfd != -1) {
    close(_M_epollfd);
  }
}

bool net::tcp::receiver::worker::listen(const char* address)
{
  return _M_listeners.listen(address);
}

bool net::tcp::receiver::worker::listen(const char* address, in_port_t port)
{
  return _M_listeners.listen(address, port);
}

bool net::tcp::receiver::worker::listen(const char* address,
                                        in_port_t minport,
                                        in_port_t maxport)
{
  return _M_listeners.listen(address, minport, maxport);
}

bool net::tcp::receiver::worker::listen(const struct sockaddr& addr,
                                        socklen_t addrlen)
{
  return _M_listeners.listen(addr, addrlen);
}

bool net::tcp::receiver::worker::listen(const socket::address& addr)
{
  return _M_listeners.listen(addr);
}

bool net::tcp::receiver::worker::start(size_t nworker,
                                       const connection::callbacks& callbacks,
                                       idle_t idle,
                                       void* user)
{
  // Open epoll file descriptor.
  _M_epollfd = epoll_create1(0);

  // If the epoll file descriptor could be opened...
  if (_M_epollfd != -1) {
    // Register listeners on the epoll instance.
    int fd;
    for (size_t i = 0; (fd = _M_listeners.fd(i)) != -1; i++) {
      struct epoll_event ev;
      ev.events = EPOLLIN | EPOLLET;

      if (static_cast<uint64_t>(fd) > _M_maxlistener) {
        _M_maxlistener = static_cast<uint64_t>(fd);
      }

      ev.data.u64 = fd;
      if (epoll_ctl(_M_epollfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        return false;
      }
    }

    // Save worker number.
    _M_nworker = nworker;

    // Save connection callbacks.
    _M_callbacks = callbacks;

    // Save idle callback.
    _M_idle = idle;

    // Save pointer to user data.
    _M_user = user;

    // Start thread.
    if (pthread_create(&_M_thread, nullptr, run, this) == 0) {
      _M_running = true;
      return true;
    }
  }

  return false;
}

void net::tcp::receiver::worker::stop()
{
  // If the thread is running...
  if (_M_running) {
    _M_running = false;
    pthread_join(_M_thread, nullptr);
  }
}

void* net::tcp::receiver::worker::run(void* arg)
{
  static_cast<worker*>(arg)->run();
  return nullptr;
}

void net::tcp::receiver::worker::run()
{
  static constexpr const int timeout = 250; // Milliseconds.
  static constexpr const int
    maxevents = static_cast<int>(connections::max_connections);

  do {
    struct epoll_event events[maxevents];

    // Wait for event.
    const int ret = epoll_wait(_M_epollfd, events, maxevents, timeout);

    switch (ret) {
      default: // At least one event was returned.
        // Process events.
        process_events(events, static_cast<size_t>(ret));
        break;
      case 0: // Timeout.
        if (_M_idle) {
          _M_idle(_M_nworker, _M_user);
        }

        break;
      case -1: // Error.
        if (errno != EINTR) {
          return;
        }

        break;
    }
  } while (_M_running);
}

void net::tcp::receiver::worker::process_events(struct epoll_event* events,
                                                size_t nevents)
{
  // For each event...
  for (size_t i = 0; i < nevents; i++) {
    // Listener?
    if (events[i].data.u64 <= _M_maxlistener) {
      // If the socket is readable...
      if (events[i].events & EPOLLIN) {
        // Accept connection(s).
        accept(events[i].data.fd);
      }
    } else {
      // Process connection.
      process(events[i].events, static_cast<connection*>(events[i].data.ptr));
    }
  }
}

void net::tcp::receiver::worker::accept(int listener)
{
  do {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(struct sockaddr_storage);

    // Accept connection.
    const int fd = accept4(listener,
                           reinterpret_cast<struct sockaddr*>(&addr),
                           &addrlen,
                           SOCK_NONBLOCK);

    // If the connection could be accepted...
    if (fd != -1) {
      // Get new connection.
      connection* const conn = _M_connections.pop();

      if (conn) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
        ev.data.ptr = conn;

        // Add connection to the epoll file descriptor.
        if (epoll_ctl(_M_epollfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
          // Initialize connection.
          conn->init(fd, addr, addrlen);

          if ((_M_callbacks.new_connection) &&
              (!_M_callbacks.new_connection(conn,
                                            _M_nworker,
                                            _M_callbacks.user))) {
            // Close connection.
            conn->close();

            // Return connection to the pool.
            _M_connections.push(conn);
          }
        } else {
          // Return connection to the pool.
          _M_connections.push(conn);

          // Close socket.
          close(fd);
        }
      } else {
        // Close socket.
        close(fd);
      }
    } else if (errno != EINTR) {
      return;
    }
  } while (true);
}

void net::tcp::receiver::worker::process(uint32_t events, connection* conn)
{
  // If not error...
  if ((events & (EPOLLERR | EPOLLHUP)) == 0) {
    // If the socket is readable...
    if (events & EPOLLIN) {
      // Mark the connection as readable.
      conn->_M_readable = true;

      // Read from the connection while it is readable.
      do {
        const size_t oldlen = conn->_M_buf.length();

        // Read from the connection.
        if (conn->read()) {
          const size_t newlen = conn->_M_buf.length();

          // If we have read some data...
          if (newlen > oldlen) {
            // Invoke callback.
            if (!_M_callbacks.data_received(static_cast<const uint8_t*>(
                                              conn->_M_buf.data()
                                            ) + oldlen,
                                            newlen - oldlen,
                                            conn,
                                            _M_nworker,
                                            _M_callbacks.user)) {
              break;
            }
          }

          // If the socket is not readable anymore...
          if (!conn->_M_readable) {
            // If the peer has not closed the connection...
            if ((events & EPOLLRDHUP) == 0) {
              return;
            } else {
              break;
            }
          }
        } else {
          break;
        }
      } while (true);
    } else if ((events & EPOLLRDHUP) == 0) {
      return;
    }
  }

  if (_M_callbacks.connection_closed) {
    _M_callbacks.connection_closed(conn, _M_nworker, _M_callbacks.user);
  }

  // Close connection.
  conn->close();

  // Return connection to the pool.
  _M_connections.push(conn);
}
