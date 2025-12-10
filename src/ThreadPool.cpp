#include "ThreadPool.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

ThreadPool::ThreadPool(bool background, size_t num_threads)
{
    if (num_threads == 0)
        num_threads = std::max<size_t>(4, std::thread::hardware_concurrency());

    printf("Using %zu threads\n", num_threads);

    for (size_t i = 0; i < num_threads; ++i)
    {
        Workers.emplace_back([this, background] {
            if (background)
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

            Runner();
        });
    }
}

ThreadPool::~ThreadPool()
{
    {
        std::lock_guard _(Lock);
        Stop = true;
    }

    TasksChanged.notify_all();

    for (auto& worker : Workers)
        worker.join();
}

void ThreadPool::run(std::function<void()> func, size_t times)
{
    bool empty = false;

    {
        std::lock_guard _(Lock);
        empty = Tasks.empty();
        Tasks.emplace_back(Task {std::move(func), times});
    }

    if (empty)
    {
        if (times > 1)
            TasksChanged.notify_all();
        else
            TasksChanged.notify_one();
    }
}

void ThreadPool::partition(size_t total, size_t partition, std::function<void(size_t, size_t)> func)
{
    std::atomic<std::size_t> current = 0;

    const auto worker = [&current, func = std::move(func), total, partition] {
        while (true)
        {
            const size_t sub_current = current.fetch_add(partition, std::memory_order_relaxed);

            if (sub_current >= total)
                break;

            func(sub_current, std::min<size_t>(partition, total - sub_current));
        }
    };

    run(std::cref(worker), (std::min)(Workers.size(), (total + partition - 1) / partition));

    wait();
}

void ThreadPool::for_n(size_t total, std::function<void(size_t)> func)
{
    partition(total, 1, [&](size_t start, size_t count) {
        for (size_t i = 0; i < count; ++i)
        {
            func(start + i);
        }
    });
}

void ThreadPool::Runner()
{
    std::unique_lock guard(Lock);

    while (true)
    {
        if (Tasks.empty())
        {
            if (Stop)
                break;

            if (Running == 0)
            {
                TasksFinished.notify_one();
            }

            TasksChanged.wait(guard);
            continue;
        }

        std::function<void()> func;

        if (auto& task = Tasks.back(); task.Repeat > 1)
        {
            func = task.Func;
            --task.Repeat;
        }
        else
        {
            func = std::move(task.Func);
            Tasks.pop_back();
        }

        ++Running;
        guard.unlock();

        func();

        guard.lock();
        --Running;
    }
}

void ThreadPool::wait()
{
    std::unique_lock guard(Lock);

    TasksFinished.wait(guard, [this] { return Tasks.empty() && (Running == 0); });
}
