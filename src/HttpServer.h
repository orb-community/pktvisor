#ifndef VIZERD_HTTPSERVER_H
#define VIZERD_HTTPSERVER_H

#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>
#include <cpp-httplib/httplib.h>

namespace vizer {
class HttpServer : public httplib::Server
{
    bool _read_only = true;

public:
    HttpServer(bool read_only)
        : _read_only(read_only)
    {
    }

    Server &Get(const char *pattern, Handler handler)
    {
        Corrade::Utility::print("Registering GET {}\n", pattern);
        return httplib::Server::Get(pattern, handler);
    }
    Server &Post(const char *pattern, Handler handler)
    {
        if (_read_only) {
            return *this;
        }
        Corrade::Utility::print("Registering POST {}\n", pattern);
        return httplib::Server::Post(pattern, handler);
    }
    Server &Put(const char *pattern, Handler handler)
    {
        if (_read_only) {
            return *this;
        }
        Corrade::Utility::print("Registering PUT {}\n", pattern);
        return httplib::Server::Put(pattern, handler);
    }
    Server &Delete(const char *pattern, Handler handler)
    {
        if (_read_only) {
            return *this;
        }
        Corrade::Utility::print("Registering DELETE {}\n", pattern);
        return httplib::Server::Delete(pattern, handler);
    }
};
}

#endif //VIZERD_HTTPSERVER_H
