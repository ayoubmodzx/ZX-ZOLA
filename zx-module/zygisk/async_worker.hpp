#pragma once
#include <functional>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

// Single background worker thread — il2cpp ops run here, never on render thread
class AsyncWorker {
public:
    using Task = std::function<void()>;

    void start();
    void stop();
    void post(Task task);
    void postDelayed(Task task, uint32_t delay_ms);

    ~AsyncWorker() { stop(); }

private:
    void loop();

    std::thread              m_thread;
    std::queue<Task>         m_queue;
    std::mutex               m_mutex;
    std::condition_variable  m_cv;
    std::atomic<bool>        m_running{false};
};
