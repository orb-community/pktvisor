#pragma once

#include <mutex>
#include <chrono>
#include <condition_variable>
#include <chrono>

class manual_event
{
public:
	explicit manual_event(bool signaled = false)
	: m_signaled(signaled) {}

	void signal()
	{
		{
			std::unique_lock lock(m_mutex);
			m_signaled = true;
		}
		m_cv.notify_all();
	}

	void wait()
	{
		std::unique_lock lock(m_mutex);
		m_cv.wait(lock, [&]() { return m_signaled != false; });
	}

	template<typename Rep, typename Period>
	bool wait_for(const std::chrono::duration<Rep, Period>& t)
	{
		std::unique_lock lock(m_mutex);
		return m_cv.wait_for(lock, t, [&]() { return m_signaled != false; });
	}

	template<typename Clock, typename Duration>
	bool wait_until(const std::chrono::time_point<Clock, Duration>& t)
	{
		std::unique_lock lock(m_mutex);
		return m_cv.wait_until(lock, t, [&]() { return m_signaled != false; });
	}

	void reset()
	{
		std::unique_lock lock(m_mutex);
		m_signaled = false;
	}

private:
	bool m_signaled = false;
	std::mutex m_mutex;
	std::condition_variable m_cv;
};

class auto_event
{
public:
	explicit auto_event(bool signaled = false)
	: m_signaled(signaled) {}

	void signal()
	{
		{
			std::unique_lock lock(m_mutex);
			m_signaled = true;
		}
		m_cv.notify_one();
	}

	void wait()
	{
		std::unique_lock lock(m_mutex);
		m_cv.wait(lock, [&]() { return m_signaled != false; });
		m_signaled = false;
	}

	template<typename Rep, typename Period>
	bool wait_for(const std::chrono::duration<Rep, Period>& t)
	{
		std::unique_lock lock(m_mutex);
		bool result = m_cv.wait_for(lock, t, [&]() { return m_signaled != false; });
		if(result) m_signaled = false;
		return result;
	}

	template<typename Clock, typename Duration>
	bool wait_until(const std::chrono::time_point<Clock, Duration>& t)
	{
		std::unique_lock lock(m_mutex);
		bool result = m_cv.wait_until(lock, t, [&]() { return m_signaled != false; });
		if(result) m_signaled = false;
		return result;
	}

private:
	bool m_signaled = false;
	std::mutex m_mutex;
	std::condition_variable m_cv;
};
