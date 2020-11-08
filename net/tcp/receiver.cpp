#include "net/tcp/receiver.h"

net::tcp::receiver::receiver(size_t nworkers)
{
  if (nworkers == 0) {
    _M_nworkers = 1;
  } else if (nworkers > max_workers) {
    _M_nworkers = max_workers;
  } else {
    _M_nworkers = nworkers;
  }
}

net::tcp::receiver::~receiver()
{
  // Stop threads (if running).
  stop();
}

bool net::tcp::receiver::listen(const char* address)
{
  socket::address addr;
  return ((addr.build(address)) && (listen(addr)));
}

bool net::tcp::receiver::listen(const char* address, in_port_t port)
{
  socket::address addr;
  return ((addr.build(address, port)) && (listen(addr)));
}

bool net::tcp::receiver::listen(const char* address,
                                in_port_t minport,
                                in_port_t maxport)
{
  // For each worker thread...
  for (size_t i = 0; i < _M_nworkers; i++) {
    // Listen.
    if (!_M_workers[i].listen(address, minport, maxport)) {
      return false;
    }
  }

  return true;
}

bool net::tcp::receiver::listen(const struct sockaddr& addr, socklen_t addrlen)
{
  // For each worker thread...
  for (size_t i = 0; i < _M_nworkers; i++) {
    // Listen.
    if (!_M_workers[i].listen(addr, addrlen)) {
      return false;
    }
  }

  return true;
}

bool net::tcp::receiver::listen(const socket::address& addr)
{
  return listen(static_cast<const struct sockaddr&>(addr), addr.length());
}

bool net::tcp::receiver::start(const connection::callbacks& callbacks,
                               idle_t idle,
                               void* user)
{
  if (callbacks.data_received) {
    // For each worker thread...
    for (size_t i = 0; i < _M_nworkers; i++) {
      // Start.
      if (!_M_workers[i].start(i, callbacks, idle, user)) {
        return false;
      }
    }

    return true;
  }

  return false;
}

void net::tcp::receiver::stop()
{
  // For each worker thread...
  for (size_t i = 0; i < _M_nworkers; i++) {
    // Stop.
    _M_workers[i].stop();
  }
}
