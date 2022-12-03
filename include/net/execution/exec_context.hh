#ifndef NET_EXEC_CONTEXT_HH
#define NET_EXEC_CONTEXT_HH

#include "../utils.hh"

#include <condition_variable>
#include <functional>
#include <queue>
#include <thread>

namespace net {

namespace detail {

#define L(x) \
x:

/// Like std::vector, but the size is fixed and the elements are
/// uninitialised and must be constructed using a placement new.
///
/// The destructor takes care of calling the destructors
template <typename _ty>
struct uninitialised_fixed_vector {
    using value_type = _ty;

    value_type* const data;
    const usz size;

    uninitialised_fixed_vector(usz sz)
        : data{reinterpret_cast<value_type*>(::new std::byte[sz * sizeof(value_type)])},
          size{sz} {}

    ~uninitialised_fixed_vector() {
        for (usz i = 0; i < size; ++i) data[i].~value_type();
        ::delete[] reinterpret_cast<std::byte*>(data);
    }

    nocopy(uninitialised_fixed_vector);
    nomove(uninitialised_fixed_vector);

    [[nodiscard]] value_type& operator[](usz i) noexcept { return data[i]; }
    [[nodiscard]] const value_type& operator[](usz i) const noexcept { return data[i]; }

    [[nodiscard]] value_type* begin() noexcept { return data; }
    [[nodiscard]] value_type* end() noexcept { return data + size; }
    [[nodiscard]] const value_type* begin() const noexcept { return data; }
    [[nodiscard]] const value_type* end() const noexcept { return data + size; }
};

/// Thread-safe wrapper around an object.
template <typename _ty>
class synchronised {
    using value_type = _ty;

    value_type value;
    std::mutex mutex;

public:
    template <typename func>
    auto with_lock(func&& f) {
        std::unique_lock lock{mutex};
        if constexpr (std::is_invocable_v<func, value_type&>) return std::invoke(std::forward<func>(f), value);
        else return std::invoke(std::forward<func>(f), value, lock);
    }
};

/// Wrapper around std::atomic_flag that calls notify_one()
/// every time the flag is set.
class atomic_cond_var {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;

public:
    atomic_cond_var() = default;
    ~atomic_cond_var() = default;
    nomove(atomic_cond_var);
    nocopy(atomic_cond_var);

    /// Send a notification.
    void notify() noexcept {
        flag.test_and_set();
        flag.notify_one();
    }

    /// Wait for a notification.
    void wait() noexcept {
        flag.clear();
        flag.wait(false);
    }
};

} // namespace detail

/// Flag used to stop the execution context.
class stop_flag {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;

public:
    stop_flag() = default;
    ~stop_flag() = default;
    nomove(stop_flag);
    nocopy(stop_flag);

    void stop() noexcept { flag.test_and_set(); }
    [[nodiscard]] bool stopped() const noexcept { return flag.test(); }
};

/// Context for threads and jobs.
///
/// This structure contains a thread pool and dispatcher that
/// is used to run jobs, async operations, and timers.
class execution_context final {
    using task_t = std::function<void(execution_context&)>;

    /// A single thread + a slot for the thread to execute.
    ///
    /// A thread can be assigned a task, which it will then run to completion.
    /// Tasks are assigned to threads as follows: Every thread has a slot for
    /// a task, a relative ID between 0 and sizeof(usz) * CHAR_BIT - 1, and an
    /// atomic flag. A thread’s entry in the mask is the relative_thread_id-th
    /// bit in the mask.
    ///
    /// When the executor wants to assign a task to a thread, it first loads the
    /// mask for the first set of threads. If the mask is all 1’s, it checks the
    /// next mask and so on. If all masks are full, it enqueues it into a queue
    /// for later.
    struct thread_context {
        execution_context& context;
        std::jthread thread;
        const usz relative_thread_id;

        /// Used to tell the main executor thread if we’re free.
        std::atomic<usz>& mask;

        /// Used to tell us that we should resume execution.
        detail::atomic_cond_var resume;

        /// The function to execute.
        task_t task;

        /// Initialise and start a thread.
        explicit thread_context(execution_context& ctx, usz id, std::atomic<usz>& _mask)
            : context(ctx), relative_thread_id(id), mask(_mask) {
            thread = std::jthread([this](std::stop_token stop) {
                while (not stop.stop_requested()) {
                    /// Wait until the context tells us that there’s a task.
                    resume.wait();

                    /// Stop if requested.
                    if (stop.stop_requested()) break;

                    /// Run the task.
                    try {
                        std::invoke(task, context);
                    } catch (const std::exception& e) {
                        /// TODO: What to do here?
                        err("Exception in worker thread: %s", e.what());
                    }

                    /// Tell the context that we’re free and that it
                    /// can enqueue the next task if there is one.
                    mask.fetch_xor(1 << relative_thread_id);
                    context.task_queue_cv.notify_one();
                }
            });
        }

        /// Nothing to do here.
        ~thread_context() = default;

        /// Copying/moving these is 1. impossible and 2. a horrible idea.
        nocopy(thread_context);
        nomove(thread_context);
    };

    /// Thread masks. These are used to determine what threads are idle.
    detail::uninitialised_fixed_vector<std::atomic<usz>> masks;

    /// Threads.
    detail::uninitialised_fixed_vector<thread_context> threads;

    /// Queue of tasks to run if all threads are busy.
    detail::synchronised<std::queue<task_t>> task_queue;

    /// Condition variable for the task queue.
    std::condition_variable task_queue_cv;

    /// Stop token for the main thread.
    std::stop_token main_stop_token{};

    /// Enqueue a task. Return false if the task was enqueued, true if it was
    /// executed immediately.
    ///
    /// This function is not exposed because the return value might
    /// be confusing and is not useful to the user.
    template <typename func, bool should_enqueue>
    [[nodiscard]] bool add_task_impl(func&& f) {
        /// Create the task.
        task_t task;
        if constexpr (std::is_invocable_v<func, execution_context&>) task = std::forward<func>(f);
        else task = [f = std::forward<func>(f)](execution_context&) { f(); };

        /// Find a thread to run it on.
        for (usz i = 0; i < masks.size; ++i) {
            usz mask = masks[i].load();
            usz thread_id;

            /// Try and find a thread that’s free.
            do {
                /// If the mask is all 1’s, skip it.
                if (mask == compl usz(0)) goto next_mask;

                /// Find the first free thread.
                thread_id = __builtin_ctzll(~mask);
            } while (not masks[i].compare_exchange_weak(mask, mask | (1 << thread_id)));

            /// Set the task and tell the thread to resume.
            threads[i * sizeof(usz) * CHAR_BIT + thread_id].task = std::move(task);
            threads[i * sizeof(usz) * CHAR_BIT + thread_id].resume.notify();

            /// We’re done.
            return true;

            /// This mask is full, try the next one.
            L (next_mask) {}
        }

        /// If we get here, all threads are busy. Enqueue the task.
        /// The queue thread already holds a lock on the queue and
        /// will enqueue the task itself, so there is no point in
        /// doing it here.
        if constexpr (should_enqueue) {
            task_queue.with_lock([&](auto& queue) { queue.push(std::move(task)); });
            task_queue_cv.notify_one();
        }

        /// We failed to execute the task immediately.
        return false;
    }

    template <typename func>
    [[nodiscard]] bool add_task_locked(func&& f) {
        return add_task_impl<func, true>(std::forward<func>(f));
    }

    template <typename func>
    [[nodiscard]] bool add_task_unlocked(func&& f) {
        return add_task_impl<func, false>(std::forward<func>(f));
    }

    /// Stop execution.
    void stop() {
        /// Wake up all threads.
        for (auto& thread : threads) {
            thread.thread.request_stop();
            thread.resume.notify();
        }

        task_queue_cv.notify_all();
    }

public:
    /// Create a new execution context.
    explicit execution_context(usz thread_count = std::thread::hardware_concurrency() ?: 2)
        : masks(thread_count / (sizeof(usz) * CHAR_BIT) + 1), threads(thread_count) {
        /// Initialise the masks.
        for (auto& mask : masks) ::new (&mask) std::atomic<usz>{0};

        /// Initialise the threads.
        for (usz i = 0; i < thread_count; ++i) {
            ::new (&threads[i]) thread_context(
                *this,
                i % (sizeof(usz) * CHAR_BIT),
                masks[i / (sizeof(usz) * CHAR_BIT)]
            );
        }
    }

    /// Tear down the execution context.
    ~execution_context() { stop(); }

    /// Add a task to the execution context.
    template <typename func>
    void add_task(func&& f) {
        (void) add_task_locked(std::forward<func>(f));
    }

    /// Flush all tasks and stop.
    void flush_and_stop() {
        stop();

        /// Run all remaining tasks.
        task_queue.with_lock([&](auto& queue) {
            while (not queue.empty()) {
                std::invoke(queue.front(), *this);
                queue.pop();
            }
        });
    }

    /// Flush all tasks and stop.
    /// Stop the run_forever() thread too.
    void flush_and_stop(stop_flag& flag) {
        flag.stop();
        flush_and_stop();
    }

    /// Run the main loop.
    void run_forever(stop_flag& stop) {
        while (not stop.stopped()) {
            /// Wait for a task.
            task_queue.with_lock([&](auto& queue, auto&& lock) {
                while (queue.empty() and not stop.stopped()) {
                    task_queue_cv.wait(lock, [&] {
                        return not queue.empty() || stop.stopped();
                    });
                }

                /// If we’re stopping, stop.
                if (stop.stopped()) return;

                /// Try to run as many tasks as possible.
                while (not queue.empty()) {
                    auto task = std::move(queue.front());
                    queue.pop();
                    if (not add_task_unlocked(task)) {
                        queue.push(std::move(task));
                        break;
                    }
                }
            });
        }
    }
};

#undef L

} // namespace net

#endif // NET_EXEC_CONTEXT_HH
