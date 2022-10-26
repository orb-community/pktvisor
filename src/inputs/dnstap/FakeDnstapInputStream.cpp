#include "FakeDnstapInputStream.h"
#include "DnstapInputEventProxy.h"

namespace visor::input::dnstap {

DnstapInputStream::DnstapInputStream(const std::string &name)
    : visor::InputStream(name)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
}

void DnstapInputStream::start()
{
    if (_running) {
        return;
    }
    _running = true;
}

void DnstapInputStream::stop()
{
    if (!_running) {
        return;
    }
    _running = false;
}

void DnstapInputStream::info_json(json &j) const
{
    common_info_json(j);
}

std::unique_ptr<InputEventProxy> DnstapInputStream::create_event_proxy(const Configurable &filter)
{
    return std::make_unique<DnstapInputEventProxy>(_name, filter);
}

}
