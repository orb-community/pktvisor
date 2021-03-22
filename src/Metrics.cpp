/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Metrics.h"
#include <cpc_union.hpp>

namespace visor {

void Counter::to_json(json &j) const
{
    name_json_assign(j, _value);
}

void Counter::to_prometheus(std::stringstream &out) const
{
    out << "# HELP " << name_snake() << ' ' << _desc << std::endl;
    out << "# TYPE " << name_snake() << " gauge" << std::endl;
    out << name_snake() << ' ' << _value << std::endl;
}

void Rate::to_json(json &j, bool include_live) const
{
    to_json(j);
    if (include_live) {
        //        name_json(j)["live"] = rate();
    }
}

void Rate::to_json(visor::json &j) const
{
    const double fractions[4]{0.50, 0.90, 0.95, 0.99};

    std::shared_lock lock(_sketch_mutex);

    auto quantiles = _quantile.get_quantiles(fractions, 4);
    if (quantiles.size()) {
        name_json_assign(j, {"p50"}, quantiles[0]);
        name_json_assign(j, {"p90"}, quantiles[1]);
        name_json_assign(j, {"p95"}, quantiles[2]);
        name_json_assign(j, {"p99"}, quantiles[3]);
    }
}

void Rate::to_prometheus(std::stringstream &out) const
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
    name_json_assign(j, lround(_set.get_estimate()));
}
void Cardinality::to_prometheus(std::stringstream &out) const
{
}

void Metric::name_json_assign(json &j, const json &val) const
{
    json *j_part = &j;
    for (const auto &s_part : _name) {
        j_part = &(*j_part)[s_part];
    }
    (*j_part) = val;
}
void Metric::name_json_assign(json &j, std::initializer_list<std::string> add_names, const json &val) const
{
    json *j_part = &j;
    for (const auto &s_part : _name) {
        j_part = &(*j_part)[s_part];
    }
    for (const auto &s_part : add_names) {
        j_part = &(*j_part)[s_part];
    }
    (*j_part) = val;
}

}