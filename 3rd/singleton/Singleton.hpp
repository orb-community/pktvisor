/**
 * from https://gist.github.com/cjmeyer/5682542
 */

#ifndef _SINGLETON_H
#define _SINGLETON_H

namespace lib {
namespace detail {
template <typename T>
struct SingletonWrapper {
    ~SingletonWrapper(void)
    {
    }

    T m_instance;
    static bool m_bool;
}; /* lib::detail::SingletonWrapper */

template <typename T>
bool lib::detail::SingletonWrapper<T>::m_bool = false;
}; /* DgLib::detail */

template <typename T>
class Singleton
{
private:
    static T &m_instance;

    /* Needed to use the static instance without accessing. */
    static void use(const T &)
    {
    }

    static T &get_instance(void)
    {
        /* This is the actual singleton instance. */
        static lib::detail::SingletonWrapper<T> wrapper;

        /* Force use of the instance...required. */
        use(m_instance);

        /* Return the singleton stored in the wrapper. Don't use our
               own 'm_instance' as it may not be initialized yet. */
        return static_cast<T &>(wrapper.m_instance);
    }

public:
    static const T &get_const(void)
    {
        return get_instance();
    }

    static T &get(void)
    {
        return get_instance();
    }
}; /* lib::Singleton */

/* This line is key. It is required in order to make the singleton statically
       initialized at runtime prior to main() running. */
template <typename T>
T &Singleton<T>::m_instance = Singleton<T>::get_instance();
}; /* lib */

#endif /* _SINGLETON_H */
