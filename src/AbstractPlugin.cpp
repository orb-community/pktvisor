#include "AbstractPlugin.h"
#include <regex>
#include <sstream>

namespace vizer {

void AbstractPlugin::_check_schema(json obj, SchemaMap &required, SchemaMap &optional)
{
    for (const auto &[key, value] : required) {
        if (!obj.contains(key)) {
            std::stringstream err;
            err << "required field is missing: " << key;
            throw SchemaException(err.str());
        }
        if (!std::regex_match(obj[key].get<std::string>(), std::regex(value))) {
            std::stringstream err;
            err << "required field fails input validation: " << key << " requires " << value;
            throw SchemaException(err.str());
        }
    }
    for (const auto &[key, value] : optional) {
        if (obj.contains(key) && !std::regex_match(obj[key].get<std::string>(), std::regex(value))) {
            std::stringstream err;
            err << "optional field fails input validation: " << key << " requires " << value;
            throw SchemaException(err.str());
        }
    }
}

void AbstractPlugin::_check_schema(json obj, SchemaMap &required)
{
    for (const auto &[key, value] : required) {
        if (!obj.contains(key)) {
            std::stringstream err;
            err << "required field is missing: " << key;
            throw SchemaException(err.str());
        }
        if (!std::regex_match(obj[key].get<std::string>(), std::regex(value))) {
            std::stringstream err;
            err << "required field fails input validation: " << key << " requires " << value;
            throw SchemaException(err.str());
        }
    }
}
}