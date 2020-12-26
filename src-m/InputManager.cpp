#include "InputManager.h"
#include "InputRegistry.h"

void pktvisor::InputManager::_setup_routes(httplib::Server &svr)
{
    //    svr.Get("/api/v1/input", [](const httplib::Request &req, httplib::Response &res) {
    //        std::string out;
    //        try {
    //            //out = metricsManager->getAppMetrics();
    //            res.set_content(out, "text/json");
    //        } catch (const std::exception &e) {
    //            res.status = 500;
    //            res.set_content(e.what(), "text/plain");
    //        }
    //    });
}
