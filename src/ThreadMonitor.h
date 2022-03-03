/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
#elif __linux__
#include <unistd.h>
#endif

#include <fstream>
#include <vector>

namespace visor {

class ThreadMonitor
{
public:
    static inline double cpu_percentage()
    {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        return 0;
#elif __APPLE__
        return 0;
#elif __linux__
        double up_time;
        std::ifstream uptime("/proc/uptime");
        uptime >> up_time;
        if (up_time <= 0) {
            return 0;
        }
        uint64_t token;
        std::vector<uint64_t> stats;
        std::ifstream stat("/proc/thread-self/stat");
        stat.ignore(' ');
        while (stat >> token) {
            stats.push_back(token);
        }
        double total_time = (stats[8] + stats[9] + stats[10] + stats[11]) / sysconf(_SC_CLK_TCK);;
        uint32_t seconds = up_time - (stats[16] / sysconf(_SC_CLK_TCK));
        return 100 * (total_time / seconds);
#endif
    }

    static inline uint64_t memory_usage()
    {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        return 0;
#elif __APPLE__
        return 0;
#elif __linux__
        uint64_t memory;
        std::string token;
        std::ifstream file("/proc/thread-self/status");
        while (file >> token) {
            if (token == "VmRSS:") {
                if (file >> memory) {
                    return memory;
                } else {
                    return 0;
                }
            }
            // Ignore the rest of the line
            file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        return 0; // Nothing found
#endif
    }
};
}
