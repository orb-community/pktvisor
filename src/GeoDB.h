/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <maxminddb.h>
#pragma GCC diagnostic pop
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <ostream>
#include <shared_mutex>
#include <string>
#include <variant>

#include "VisorLRUList.h"

namespace visor::geo {

struct City {
    std::string location;
    std::string latitude;
    std::string longitude;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(City, location, latitude, longitude);

    bool operator==(const City &other) const
    {
        return (location == other.location
            && latitude == other.latitude
            && longitude == other.longitude);
    }

    friend std::ostream &operator<<(std::ostream &os, const City &c);
};

class MaxmindDB
{
    static constexpr size_t DEFAULT_CACHE_SIZE = 10000;

public:
    ~MaxmindDB();

    void enable(const std::string &database_filename, int cache_size = DEFAULT_CACHE_SIZE);
    bool enabled() const
    {
        return _enabled;
    }

    /*
     * These routines accept both IPv4 and IPv6
     */
    City getGeoLoc(const char *ip_address) const;
    City getGeoLoc(const struct sockaddr *sa) const;
    City getGeoLoc(const struct sockaddr_in *sa4) const;
    City getGeoLoc(const struct sockaddr_in6 *sa6) const;

    std::string getASNString(const char *ip_address) const;
    std::string getASNString(const struct sockaddr *sa) const;
    std::string getASNString(const struct sockaddr_in *sa4) const;
    std::string getASNString(const struct sockaddr_in6 *sa6) const;

private:
    mutable MMDB_s _mmdb;
    bool _enabled = false;
    std::unique_ptr<LRUList<std::string, std::variant<std::string, City>>> _lru_cache;
    mutable std::shared_mutex _cache_mutex;

    City _getGeoLoc(MMDB_lookup_result_s *lookup) const;
    std::string _getASNString(MMDB_lookup_result_s *lookup) const;
};

MaxmindDB &GeoIP();
MaxmindDB &GeoASN();

}

template <>
struct std::hash<visor::geo::City> {
    std::size_t operator()(const visor::geo::City &c) const
    {
        return std::hash<std::string>{}(c.location + c.latitude + c.latitude);
    }
};
