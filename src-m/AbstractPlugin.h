#ifndef PKTVISORD_ABSTRACTPLUGIN_H
#define PKTVISORD_ABSTRACTPLUGIN_H

#include "HttpServer.h"
#include <Corrade/PluginManager/AbstractPlugin.h>
#include <exception>
#include <json/json.hpp>
#include <string>
#include <unordered_map>

namespace pktvisor {

using json = nlohmann::json;

class SchemaException : public std::runtime_error
{
public:
    explicit SchemaException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class AbstractPlugin : public Corrade::PluginManager::AbstractPlugin
{
public:
    typedef const std::unordered_map<std::string, std::string> SchemaMap;

protected:
    void _check_schema(json obj, SchemaMap &required);
    void _check_schema(json obj, SchemaMap &required, SchemaMap &optional);
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
