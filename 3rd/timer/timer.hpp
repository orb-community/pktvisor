#pragma once

#include <list>
#include <mutex>
#include <tuple>
#include <atomic>
#include <thread>
#include <chrono>
#include <memory>
#include <iterator>
#include <stdexcept>
#include <functional>
#include <cstdint>
#include "event.hpp"

class timer
{
public:
	template<typename R, typename P>
	explicit timer(const std::chrono::duration<R, P>& tick)
	: m_tick{ std::chrono::duration_cast<std::chrono::nanoseconds>(tick) }
	{
		if(m_tick.count() <= 0)
		{
			throw std::invalid_argument("Invalid tick value: must be greater than zero!");
		}

		m_tick_thread = std::make_unique<std::thread>([this]()
		{
			auto start = std::chrono::steady_clock::now();

			while(!m_tick_event.wait_until(start + m_tick * ++m_ticks))
			{
				std::scoped_lock lock{ m_events_lock };

				auto it = std::begin(m_events);
				auto end = std::end(m_events);

				while(it != end)
				{
					auto& e = *it;

					if(e->elapsed += m_tick.count(); e->elapsed >= e->ticks)
					{
						if(auto remove = e->proc())
						{
							m_events.erase(it++);
							continue;
						}
						else
						{
							e->elapsed = 0;
						}
					}

					++it;
				}
			}
		});
	}

	~timer()
	{
		m_tick_event.signal();
		m_tick_thread->join();
	}

	using manual_event_ptr = std::shared_ptr<manual_event>;
	using auto_event_ptr = std::shared_ptr<auto_event>;

	template<typename C, typename W>
	struct event_handle
	{
		event_handle(C cancel_event, W work_event)
		: m_cancel_event{ cancel_event }, m_work_event{ work_event } {}

		void cancel() { m_cancel_event->signal(); }

		void wait() { m_work_event->wait(); }

		template<typename Rep, typename Period>
		bool wait_for(const std::chrono::duration<Rep, Period>& t) { return m_work_event->wait_for(t); }

		template<typename Clock, typename Duration>
		bool wait_until(const std::chrono::time_point<Clock, Duration>& t) { return m_work_event->wait_until(t); }

	private:
		C m_cancel_event;
		W m_work_event;
	};

	using timeout_handle = event_handle<manual_event_ptr, manual_event_ptr>;
	using interval_handle = event_handle<manual_event_ptr, auto_event_ptr>;

	template<typename R, typename P, typename F, typename... Args>
	[[nodiscard]] auto set_timeout(const std::chrono::duration<R, P>& timeout, F&& f, Args&&... args)
	{
		if(timeout.count() <= 0)
		{
			throw std::invalid_argument("Invalid timeout value: must be greater than zero!");
		}

		auto cancel_event = std::make_shared<manual_event>();
		auto work_event = std::make_shared<manual_event>();
		auto handle = std::make_shared<timeout_handle>(cancel_event, work_event);

		auto ctx = std::make_shared<event_ctx>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count(),
			[=, p = std::forward<F>(f), t = std::make_tuple(std::forward<Args>(args)...)]() mutable
			{
				if(cancel_event->wait_for(std::chrono::seconds{0}))
				{
					return true;
				}

				std::apply(p, t);
				work_event->signal();

				return true;
			});

		{
			std::scoped_lock lock{ m_events_lock };
			m_events.push_back(ctx);
		}

		return handle;
	}

	template<typename R, typename P, typename F, typename... Args>
	[[nodiscard]] auto set_interval(const std::chrono::duration<R, P>& interval, F&& f, Args&&... args)
	{
		if(interval.count() <= 0)
		{
			throw std::invalid_argument("Invalid interval value: must be greater than zero!");
		}

		auto cancel_event = std::make_shared<manual_event>();
		auto work_event = std::make_shared<auto_event>();
		auto handle = std::make_shared<interval_handle>(cancel_event, work_event);

		auto ctx = std::make_shared<event_ctx>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(interval).count(),
			[=, p = std::forward<F>(f), t = std::make_tuple(std::forward<Args>(args)...)]() mutable
			{
				if(cancel_event->wait_for(std::chrono::seconds{0}))
				{
					return true;
				}

				std::apply(p, t);
				work_event->signal();

				return false;
			});

		{
			std::scoped_lock lock{ m_events_lock };
			m_events.push_back(ctx);
		}

		return handle;
	}

private:
	std::chrono::nanoseconds m_tick;
	std::uint64_t m_ticks = 0;

	using thread_ptr = std::unique_ptr<std::thread>;
	thread_ptr m_tick_thread;
	manual_event m_tick_event;

	struct event_ctx
	{
		using proc_t = std::function<bool(void)>;

		event_ctx(std::uint64_t t, proc_t&& p)
		: ticks{ t }, proc{ std::move(p) } {}

		std::uint32_t seq_num = s_next.fetch_add(1);
		std::uint64_t ticks;
		std::uint64_t elapsed = 0;
		proc_t proc;

	private:
		static inline std::atomic_uint32_t s_next = 0;
	};

	using event_ctx_ptr = std::shared_ptr<event_ctx>;
	using event_list = std::list<event_ctx_ptr>;
	event_list m_events;
	std::recursive_mutex m_events_lock;
};
