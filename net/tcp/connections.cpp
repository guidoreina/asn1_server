#include <stdlib.h>
#include <new>
#include "net/tcp/connections.h"
#include "net/tcp/connection.h"

net::tcp::connections::~connections()
{
  erase(_M_connections);
  erase(_M_free);
}

net::tcp::connection* net::tcp::connections::pop()
{
  // Allocate connection (if needed).
  if (allocate()) {
    connection* const conn = _M_free;

    _M_free = _M_free->_M_next;

    conn->_M_prev = nullptr;
    conn->_M_next = _M_connections;

    if (_M_connections) {
      _M_connections->_M_prev = conn;
    }

    _M_connections = conn;

    _M_nconnections++;

    return conn;
  }

  return nullptr;
}

void net::tcp::connections::push(connection* conn)
{
  // If not the first connection...
  if (conn->_M_prev) {
    conn->_M_prev->_M_next = conn->_M_next;
  } else {
    _M_connections = conn->_M_next;
  }

  // If not the last connection...
  if (conn->_M_next) {
    conn->_M_next->_M_prev = conn->_M_prev;
  }

  conn->_M_next = _M_free;
  _M_free = conn;

  _M_nconnections--;
}

void net::tcp::connections::erase(const connection* conn)
{
  while (conn) {
    const connection* const next = conn->_M_next;

    delete conn;

    conn = next;
  }
}

bool net::tcp::connections::allocate()
{
  // If there are free connections...
  if (_M_free) {
    return true;
  } else {
    // Compute the maximum number of connections which could be allocated.
    const size_t max = max_connections - _M_nconnections;

    for (size_t i = (allocation <= max) ?  allocation : max; i > 0; i--) {
      // Create new connection.
      connection* const conn = new (std::nothrow) connection();

      // If the connection could be created...
      if (conn) {
        conn->_M_next = _M_free;
        _M_free = conn;
      } else {
        break;
      }
    }

    return (_M_free != nullptr);
  }
}
