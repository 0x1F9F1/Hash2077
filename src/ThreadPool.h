#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

class ThreadPool {
public:
    ThreadPool(bool background, size_t num_threads = 0);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    void run(std::function<void()> func, size_t times = 1);
    void partition(size_t total, size_t partition, std::function<void(size_t, size_t)> func);
    void for_n(size_t total, std::function<void(size_t)> func);

    void wait();

private:
    void Runner();

    struct Task {
        std::function<void()> Func;
        size_t Repeat = 0;
    };

    std::mutex Lock;
    std::vector<std::thread> Workers;
    std::vector<Task> Tasks;
    std::condition_variable TasksChanged;
    std::condition_variable TasksFinished;
    size_t Running = 0;

    bool Stop = false;
};