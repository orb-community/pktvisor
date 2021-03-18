/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Metrics.h"
#include <cpc_union.hpp>

namespace visor {

void Counter::to_json(visor::json &j) const
{
    j[_name] = _value;
}

void Counter::to_prometheus(std::stringstream &out, const std::string &key) const
{
    out << "# HELP " << key << "_" << _name << ' ' << _desc << std::endl;
    out << "# TYPE " << key << "_" << _name << " gauge" << std::endl;
    out << key << '_' << _name << ' ' << _value << std::endl;
}

void Rate::to_json(json &j, bool include_live) const
{
    to_json(j);
    if (include_live) {
        j[_name]["live"] = rate();
    }
}

void Rate::to_json(visor::json &j) const
{
    const double fractions[4]{0.50, 0.90, 0.95, 0.99};

    std::shared_lock lock(_sketch_mutex);

    auto quantiles = _quantile.get_quantiles(fractions, 4);
    if (quantiles.size()) {
        j[_name]["p50"] = quantiles[0];
        j[_name]["p90"] = quantiles[1];
        j[_name]["p95"] = quantiles[2];
        j[_name]["p99"] = quantiles[3];
    }
}

void Rate::to_prometheus(std::stringstream &out, const std::string &key) const
{
    /*
    out << "# HELP " << key << "_" << _name << ' ' << _desc << std::endl;
    out << "# TYPE " << key << "_" << _name << " gauge" << std::endl;
    out << key << '_' << _name << ' ' << _value << std::endl;
     */
}

void Cardinality::merge(const Cardinality &other)
{
    datasketches::cpc_union merge_set;
    merge_set.update(_set);
    merge_set.update(other._set);
    _set = merge_set.get_result();
}
void Cardinality::to_json(json &j) const
{
    j[_name] = lround(_set.get_estimate());
}
void Cardinality::to_prometheus(std::stringstream &out, const std::string &key) const
{
}

}