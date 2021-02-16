#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace vizer {

// adapted from https://codereview.stackexchange.com/questions/40915/simple-multithread-timer
class Timer
{
public:
    typedef std::chrono::milliseconds Interval;
    typedef std::function<void(void)> Timeout;

    Timer(Timer::Timeout timeout,
        const Timer::Interval &interval,
        bool singleShot)
        : _isSingleShot(singleShot)
        , _interval(interval)
        , _timeout(std::move(timeout))
    {
    }

    ~Timer() {
        stop();
    }

    void start()
    {
        if (_running)
            return;

        _running = true;

        _thread = std::thread(
            &Timer::_temporize, this);
    }

    void stop()
    {
        if (!_running)
            return;
        _running = false;
        _thread.join();
    }

    bool running() const
    {
        return _running;
    }

    const Timer::Interval &interval() const
    {
        return _interval;
    }

    const Timeout &timeout() const
    {
        return _timeout;
    }

private:
    std::thread _thread;

    std::atomic_bool _running = false;
    bool _isSingleShot = true;

    Interval _interval = Interval(0);
    Timeout _timeout = nullptr;

    void _temporize()
    {
        if (_isSingleShot) {
            _sleepThenTimeout();
        } else {
            while (_running) {
                _sleepThenTimeout();
            }
        }
    }

    void _sleepThenTimeout()
    {
        std::this_thread::sleep_for(_interval);

        if (_running)
            timeout()();
    }
};

}