#include "AbstractPlugin.h"
#include <regex>
#include <sstream>

namespace pktvisor {

void AbstractPlugin::_check_schema(json obj, const std::unordered_map<std::string, std::string> &required)
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