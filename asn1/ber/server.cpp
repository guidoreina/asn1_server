#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "asn1/ber/server.h"
#include "asn1/ber/decoder.h"

asn1::ber::server::~server()
{
  // Stop receiver (if running).
  _M_receiver.stop();

  if (_M_files) {
    for (size_t i = _M_receiver.number_workers(); i > 0; i--) {
      if (_M_files[i - 1].f) {
        move(_M_files[i - 1]);
      }
    }

    free(_M_files);
  }
}

bool asn1::ber::server::start(const char* tempdir,
                              const char* finaldir,
                              size_t maxfilesize,
                              time_t maxfileage)
{
  const size_t tempdirlen = strlen(tempdir);
  const size_t finaldirlen = strlen(finaldir);

  struct stat sbuf;
  if ((tempdirlen < sizeof(_M_tempdir)) &&
      (finaldirlen < sizeof(_M_finaldir)) &&
      (maxfilesize >= min_file_size) &&
      (maxfilesize <= max_file_size) &&
      (maxfileage >= min_file_age) &&
      (maxfileage <= max_file_age) &&
      (stat(tempdir, &sbuf) == 0) &&
      (S_ISDIR(sbuf.st_mode)) &&
      (stat(finaldir, &sbuf) == 0) &&
      (S_ISDIR(sbuf.st_mode))) {
    _M_files = static_cast<file*>(
                 malloc(_M_receiver.number_workers() * sizeof(file))
               );

    if (_M_files) {
      for (size_t i = _M_receiver.number_workers(); i > 0; i--) {
        _M_files[i - 1].f = nullptr;
        _M_files[i - 1].count = 0;
        _M_files[i - 1].timestamp_last_file = 0;
      }

      memcpy(_M_tempdir, tempdir, tempdirlen);
      _M_tempdir[tempdirlen] = 0;

      memcpy(_M_finaldir, finaldir, finaldirlen);
      _M_finaldir[finaldirlen] = 0;

      _M_maxfilesize = maxfilesize;
      _M_maxfileage = maxfileage;

      net::tcp::connection::callbacks callbacks(new_connection,
                                                data_received,
                                                connection_closed,
                                                this);

      // Start TCP receiver.
      return _M_receiver.start(callbacks, idle, this);
    }
  }

  return false;
}

bool asn1::ber::server::new_connection(net::tcp::connection* conn,
                                       size_t nworker)
{
  return true;
}

bool asn1::ber::server::data_received(const void* data,
                                      size_t len,
                                      net::tcp::connection* conn,
                                      size_t nworker)
{
  // Get current time.
  const time_t now = time(nullptr);

  string::buffer& buf = conn->buffer();

  const uint8_t* const begin = static_cast<const uint8_t*>(buf.data());

  const uint8_t* p = begin;
  len = buf.length();

  do {
    decoder decoder(p, len);

    value val;

    switch (decoder.next(val)) {
      case decoder::result::no_error:
        // Write record.
        if (write(nworker, p, val.total_length(), now)) {
          // Skip record.
          p += val.total_length();
          len -= val.total_length();
        } else {
          return false;
        }

        break;
      case decoder::result::unexpected_eof:
        if (p != begin) {
          // Remove the first `p - begin` bytes.
          buf.erase(0, p - begin);
        }

        return true;
      default:
        return false;
    }
  } while (true);
}

void asn1::ber::server::connection_closed(net::tcp::connection* conn,
                                          size_t nworker)
{
}

void asn1::ber::server::idle(size_t nworker)
{
  // If the file is open and has not been updated for a while...
  if ((_M_files[nworker].f) &&
      (time(nullptr) - _M_files[nworker].timestamp_last_write >
       _M_maxfileage)) {
    // Close file and move it to the final directory.
    move(_M_files[nworker]);
  }
}

bool asn1::ber::server::open(size_t nworker, time_t now)
{
  struct tm tm;
  localtime_r(&now, &tm);

  file* const file = &_M_files[nworker];

  file->count = (now != file->timestamp_last_file) ? 0 : file->count + 1;

  // Compose filename.
  snprintf(file->name,
           sizeof(file->name),
           "%04u%02u%02u-%02u%02u%02u-%03zu-%06zu.asn1",
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           nworker,
           file->count);

  // Compose pathname.
  char pathname[PATH_MAX];
  snprintf(pathname, sizeof(pathname), "%s/%s", _M_tempdir, file->name);

  // Open file.
  file->f = fopen(pathname, "w");

  // If the file could be opened...
  if (file->f) {
    file->size = 0;
    file->timestamp_last_file = now;

    return true;
  } else {
    return false;
  }
}

bool asn1::ber::server::move(file& file) const
{
  // Close file.
  fclose(file.f);
  file.f = nullptr;

  // Compose pathname in the temporary directory.
  char oldpath[PATH_MAX];
  snprintf(oldpath, sizeof(oldpath), "%s/%s", _M_tempdir, file.name);

  // Compose pathname in the final directory.
  char newpath[PATH_MAX];
  snprintf(newpath, sizeof(newpath), "%s/%s", _M_finaldir, file.name);

  // Move file.
  return (rename(oldpath, newpath) == 0);
}

bool asn1::ber::server::write(size_t nworker,
                              const void* buf,
                              size_t len,
                              time_t now)
{
  file* const file = &_M_files[nworker];

  // If the file has not been opened yet...
  if (!file->f) {
    // Open file.
    if (!open(nworker, now)) {
      return false;
    }
  }

  // Write to the file.
  if (fwrite(buf, 1, len, file->f) == len) {
    file->size += len;
    file->timestamp_last_write = now;

    return (file->size < _M_maxfilesize) ? true : move(*file);
  } else {
    return false;
  }
}
