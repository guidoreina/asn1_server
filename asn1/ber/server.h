#ifndef ASN1_BER_SERVER_H
#define ASN1_BER_SERVER_H

#include <stdio.h>
#include <time.h>
#include "net/tcp/receiver.h"

namespace asn1 {
  namespace ber {
    // ASN.1 BER server.
    class server {
      public:
        // Minimum file size.
        static constexpr const size_t min_file_size = 1;

        // Maximum file size.
        static constexpr const size_t max_file_size = 4 * 1024 * 1024;

        // Minimum file age (seconds).
        static constexpr const time_t min_file_age = 1;

        // Maximum file age (seconds).
        static constexpr const time_t max_file_age = 3600;

        // Constructor.
        server(size_t nworkers = net::tcp::receiver::default_workers);

        // Destructor.
        ~server();

        // Listen.
        bool listen(const char* address);
        bool listen(const char* address, in_port_t port);
        bool listen(const char* address, in_port_t minport, in_port_t maxport);
        bool listen(const struct sockaddr& addr, socklen_t addrlen);

        // Start.
        bool start(const char* tempdir,
                   const char* finaldir,
                   size_t maxfilesize,
                   time_t maxfileage);

        // Stop.
        void stop();

      private:
        // TCP receiver.
        net::tcp::receiver _M_receiver;

        // Temporary directory where to store the ASN.1 files.
        char _M_tempdir[PATH_MAX];

        // Final directory where to store the ASN.1 files.
        char _M_finaldir[PATH_MAX];

        // Files for the ASN.1 records (one per worker thread).
        struct file {
          // File name.
          char name[PATH_MAX];

          // File pointer.
          FILE* f;

          // File size.
          size_t size;

          // Number of files in the same second.
          size_t count;

          // Timestamp of the last file.
          time_t timestamp_last_file;

          // Timestamp of the last write.
          time_t timestamp_last_write;
        };

        file* _M_files = nullptr;

        // Maximum file size.
        size_t _M_maxfilesize;

        // Maximum file age.
        time_t _M_maxfileage;

        // New connection callback.
        static bool new_connection(net::tcp::connection* conn,
                                   size_t nworker,
                                   void* user);

        bool new_connection(net::tcp::connection* conn, size_t nworker);

        // Data received callback.
        static bool data_received(const void* data,
                                  size_t len,
                                  net::tcp::connection* conn,
                                  size_t nworker,
                                  void* user);

        bool data_received(const void* data,
                           size_t len,
                           net::tcp::connection* conn,
                           size_t nworker);

        // Connection closed callback.
        static void connection_closed(net::tcp::connection* conn,
                                      size_t nworker,
                                      void* user);

        void connection_closed(net::tcp::connection* conn, size_t nworker);

        // Idle callback.
        static void idle(size_t nworker, void* user);
        void idle(size_t nworker);

        // Open file.
        bool open(size_t nworker, time_t now);

        // Close and move file to the final directory.
        bool move(file& file) const;

        // Write record.
        bool write(size_t nworker,
                   const void* buf,
                   size_t len,
                   time_t now);

        // Disable copy constructor and assignment operator.
        server(const server&) = delete;
        server& operator=(const server&) = delete;
    };

    inline server::server(size_t nworkers)
      : _M_receiver(nworkers)
    {
    }

    inline bool server::listen(const char* address)
    {
      return _M_receiver.listen(address);
    }

    inline bool server::listen(const char* address, in_port_t port)
    {
      return _M_receiver.listen(address, port);
    }

    inline bool server::listen(const char* address,
                               in_port_t minport,
                               in_port_t maxport)
    {
      return _M_receiver.listen(address, minport, maxport);
    }

    inline bool server::listen(const struct sockaddr& addr, socklen_t addrlen)
    {
      return _M_receiver.listen(addr, addrlen);
    }

    inline void server::stop()
    {
      _M_receiver.stop();
    }

    inline bool server::new_connection(net::tcp::connection* conn,
                                       size_t nworker,
                                       void* user)
    {
      return static_cast<server*>(user)->new_connection(conn, nworker);
    }

    inline bool server::data_received(const void* data,
                                      size_t len,
                                      net::tcp::connection* conn,
                                      size_t nworker,
                                      void* user)
    {
      return static_cast<server*>(user)->data_received(data,
                                                       len,
                                                       conn,
                                                       nworker);
    }

    inline void server::connection_closed(net::tcp::connection* conn,
                                          size_t nworker,
                                          void* user)
    {
      static_cast<server*>(user)->connection_closed(conn, nworker);
    }

    inline void server::idle(size_t nworker, void* user)
    {
      static_cast<server*>(user)->idle(nworker);
    }
  }
}

#endif // ASN1_BER_SERVER_H
