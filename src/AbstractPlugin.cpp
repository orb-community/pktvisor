/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "AbstractPlugin.h"
#include <regex>
#include <sstream>

namespace visor {

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