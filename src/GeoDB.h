/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <maxminddb.h>
#pragma GCC diagnostic pop
#include <string>
#include <memory>

#include "LruList.h"

namespace visor::geo {

class MaxmindDB
{
public:
    ~MaxmindDB();

    void enable(const std::string &database_filename, int cache_size = 10000);
    bool enabled() const
    {
        return _enabled;
    }

    /*
     * These routines accept both IPv4 and IPv6
     */
    std::string getGeoLocString(const char *ip_address) const;
    std::string getGeoLocString(const struct sockaddr *sa) const;

    std::string getASNString(const char *ip_address) const;
    std::string getASNString(const struct sockaddr *sa) const;

private:
    mutable MMDB_s _mmdb;
    bool _enabled = false;
    std::unique_ptr<LRUList<std::string, std::string>> _lru_cache;

    std::string _getGeoLocString(MMDB_lookup_result_s *lookup) const;
    std::string _getASNString(MMDB_lookup_result_s *lookup) const;
};

MaxmindDB &GeoIP();
MaxmindDB &GeoASN();
bool enabled();

}
