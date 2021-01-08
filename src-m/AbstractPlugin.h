#ifndef PKTVISORD_ABSTRACTPLUGIN_H
#define PKTVISORD_ABSTRACTPLUGIN_H

#include "HttpServer.h"
#include <Corrade/PluginManager/AbstractPlugin.h>
#include <exception>
#include <json/json.hpp>
#include <string>
#include <unordered_map>

using json = nlohmann::json;

namespace pktvisor {

class SchemaException : public std::exception
{
private:
    std::string _message;

public:
    explicit SchemaException(const std::string &message)
        : std::exception()
        , _message(message){};
    const char *what() const noexcept override
    {
        return _message.c_str();
    }
};

class AbstractPlugin : public Corrade::PluginManager::AbstractPlugin
{
protected:
    void _check_schema(json obj, const std::unordered_map<std::string, std::string> &required);
    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::vector<std::string> pluginSearchPaths()
    {
        return {""};
    }

    explicit AbstractPlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : Corrade::PluginManager::AbstractPlugin{manager, plugin}
    {
    }

    virtual std::string name() const = 0;
};

}

#endif //PKTVISORD_ABSTRACTPLUGIN_H
