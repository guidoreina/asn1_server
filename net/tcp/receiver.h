#ifndef NET_TCP_RECEIVER_H
#define NET_TCP_RECEIVER_H

#include <stdint.h>
#include <pthread.h>
#include <sys/epoll.h>
#include "net/tcp/listeners.h"
#include "net/tcp/connections.h"
#include "net/tcp/connection.h"

namespace net {
  namespace tcp {
    // TCP receiver.
    class receiver {
      public:
        // Maximum number of worker threads.
        static constexpr const size_t max_workers = 32;

        // Default number of worker threads.
        static constexpr const size_t default_workers = 1;

        // Idle callback.
        typedef void (*idle_t)(size_t, void*);

        // Constructor.
        receiver(size_t nworkers = default_workers);

        // Destructor.
        ~receiver();

        // Listen.
        bool listen(const char* address);
        bool listen(const char* address, in_port_t port);
        bool listen(const char* address, in_port_t minport, in_port_t maxport);
        bool listen(const struct sockaddr& addr, socklen_t addrlen);
        bool listen(const socket::address& addr);

        // Start.
        bool start(const connection::callbacks& callbacks,
                   idle_t idle = nullptr,
                   void* user = nullptr);

        // Stop.
        void stop();

        // Get number of worker threads.
        size_t number_workers() const;

      private:
        // Worker thread.
        class worker {
          public:
            // Constructor.
            worker() = default;

            // Destructor.
            ~worker();

            // Listen.
            bool listen(const char* address);
            bool listen(const char* address, in_port_t port);
            bool listen(const char* address, in_port_t minport, in_port_t maxport);
            bool listen(const struct sockaddr& addr, socklen_t addrlen);
            bool listen(const socket::address& addr);

            // Start.
            bool start(size_t nworker,
                       const connection::callbacks& callbacks,
                       idle_t idle,
                       void* user);

            // Stop.
            void stop();

          private:
            // Worker number.
            size_t _M_nworker;

            // Epoll file descriptor.
            int _M_epollfd = -1;

            // Listeners.
            listeners _M_listeners;

            // Highest file descriptor of the listeners.
            uint64_t _M_maxlistener = 0;

            // Connections.
            connections _M_connections;

            // Connection callbacks.
            connection::callbacks _M_callbacks;

            // Idle callback.
            idle_t _M_idle;

            // Pointer to user data.
            void* _M_user;

            // Thread id.
            pthread_t _M_thread;

            // Running?
            bool _M_running = false;

            // Run.
            static void* run(void* arg);
            void run();

            // Process events.
            void process_events(struct epoll_event* events, size_t nevents);

            // Accept connection(s).
            void accept(int listener);

            // Process connection.
            void process(uint32_t events, connection* conn);

            // Disable copy constructor and assignment operator.
            worker(const worker&) = delete;
            worker& operator=(const worker&) = delete;
        };

        // Worker threads.
        worker _M_workers[max_workers];
        size_t _M_nworkers = 0;

        // Disable copy constructor and assignment operator.
        receiver(const receiver&) = delete;
        receiver& operator=(const receiver&) = delete;
    };

    inline size_t receiver::number_workers() const
    {
      return _M_nworkers;
    }
  }
}

#endif // NET_TCP_RECEIVER_H
