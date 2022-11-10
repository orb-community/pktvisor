/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
#include <httplib.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <spdlog/spdlog.h>

namespace visor {

using namespace httplib;

struct HttpConfig {
    bool read_only{true};
    bool tls_enabled{false};
    std::string cert;
    std::string key;
};

class HttpServer
{
    HttpConfig _config;
    std::unique_ptr<httplib::Server> _svr;

public:
    HttpServer(const HttpConfig &config)
        : _config(config)
    {
        if (config.tls_enabled) {
            _svr = std::make_unique<httplib::SSLServer>(config.cert.c_str(), config.key.c_str());
            if (!_svr->is_valid()) {
                throw std::runtime_error("invalid TLS configuration");
            }
        } else {
            _svr = std::make_unique<httplib::Server>();
        }
        _svr->set_socket_options(std::bind(&HttpServer::socket_options, this, std::placeholders::_1));
    }

    inline void socket_options(socket_t sock)
    {
        int yes = 1;
#ifdef _WIN32
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&yes), sizeof(yes));
        setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char *>(&yes), sizeof(yes));
#else
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&yes), sizeof(yes));
#endif
    }

    void set_logger(Logger logger)
    {
        _svr->set_logger(std::move(logger));
    }

    bool bind_to_port(const char *host, int port, int socket_flags = 0)
    {
        return _svr->bind_to_port(host, port, socket_flags);
    }

    bool listen_after_bind()
    {
        return _svr->listen_after_bind();
    }

    void stop()
    {
        _svr->stop();
    }

    Server &Get(const char *pattern, Server::Handler handler)
    {
        spdlog::get("visor")->info("Registering GET {}", pattern);
        return _svr->Get(pattern, handler);
    }
    Server &Post(const char *pattern, Server::Handler handler)
    {
        if (_config.read_only) {
            return *_svr;
        }
        spdlog::get("visor")->info("Registering POST {}", pattern);
        return _svr->Post(pattern, handler);
    }
    Server &Put(const char *pattern, Server::Handler handler)
    {
        if (_config.read_only) {
            return *_svr;
        }
        spdlog::get("visor")->info("Registering PUT {}", pattern);
        return _svr->Put(pattern, handler);
    }
    Server &Delete(const char *pattern, Server::Handler handler)
    {
        if (_config.read_only) {
            return *_svr;
        }
        spdlog::get("visor")->info("Registering DELETE {}", pattern);
        return _svr->Delete(pattern, handler);
    }
};
}
