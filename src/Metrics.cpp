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
    out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
    out << "# TYPE " << base_name_snake() << " gauge" << std::endl;
    out << name_snake() << ' ' << _value << std::endl;
}

void Rate::to_json(json &j, bool include_live) const
{
    to_json(j);
    if (include_live) {
        name_json_assign(j, {"live"}, rate());
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
    const double fractions[4]{0.50, 0.90, 0.95, 0.99};

    std::shared_lock lock(_sketch_mutex);
    auto quantiles = _quantile.get_quantiles(fractions, 4);

    if (quantiles.size()) {
        out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
        out << "# TYPE " << base_name_snake() << " summary" << std::endl;
        out << name_snake({}, {{"quantile", "0.5"}}) << ' ' << quantiles[0] << std::endl;
        out << name_snake({}, {{"quantile", "0.9"}}) << ' ' << quantiles[1] << std::endl;
        out << name_snake({}, {{"quantile", "0.95"}}) << ' ' << quantiles[2] << std::endl;
        out << name_snake({}, {{"quantile", "0.99"}}) << ' ' << quantiles[3] << std::endl;
        out << name_snake({"sum"}) << ' ' << _quantile.get_max_value() << std::endl;
        out << name_snake({"count"}) << ' ' << _quantile.get_n() << std::endl;
    }
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
    out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
    out << "# TYPE " << base_name_snake() << " gauge" << std::endl;
    out << name_snake() << ' ' << lround(_set.get_estimate()) << std::endl;
}

// static storage for base labels
Metric::LabelMap Metric::_base_labels;

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
std::string Metric::base_name_snake() const
{
    auto snake = [](const std::string &ss, const std::string &s) {
        return ss.empty() ? s : ss + "_" + s;
    };
    std::string name_text = _schema_key + "_" + std::accumulate(std::begin(_name), std::end(_name), std::string(), snake);
    return name_text;
}

std::string Metric::name_snake(std::initializer_list<std::string> add_names, Metric::LabelMap add_labels) const
{
    std::string label_text{"{"};
    if (!_base_labels.empty()) {
        for (const auto &[key, value] : _base_labels) {
            label_text.append(key + "=\"" + value + "\",");
        }
    }
    if (add_labels.size()) {
        for (const auto &[key, value] : add_labels) {
            label_text.append(key + "=\"" + value + "\",");
        }
    }
    if (label_text.back() == ',') {
        label_text.pop_back();
    }
    label_text.push_back('}');
    auto snake = [](const std::string &ss, const std::string &s) {
        return ss.empty() ? s : ss + "_" + s;
    };
    std::string name_text = _schema_key + "_" + std::accumulate(std::begin(_name), std::end(_name), std::string(), snake);
    if (add_names.size()) {
        name_text.push_back('_');
        name_text.append(std::accumulate(std::begin(add_names), std::end(add_names), std::string(), snake));
    }
    return name_text + label_text;
}

}