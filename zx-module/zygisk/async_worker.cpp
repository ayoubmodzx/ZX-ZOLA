#include "async_worker.hpp"
#include <chrono>
#include <android/log.h>

#define TAG "ZX-WORKER"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

void AsyncWorker::start() {
    m_running = true;
    m_thread  = std::thread(&AsyncWorker::loop, this);
    // Drop to background priority — NEVER compete with render thread
    struct sched_param param{ .sched_priority = 0 };
    sched_setscheduler(m_thread.native_handle(), SCHED_IDLE, &param);
    pthread_setname_np(m_thread.native_handle(), "zx-worker");
    LOGI("Worker thread started");
}

void AsyncWorker::stop() {
    if (!m_running) return;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_running = false;
    }
    m_cv.notify_one();
    if (m_thread.joinable()) m_thread.join();
}

void AsyncWorker::post(Task task) {
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_queue.push(std::move(task));
    }
    m_cv.notify_one();
}

void AsyncWorker::postDelayed(Task task, uint32_t delay_ms) {
    // Wrap in a delayed lambda — still runs on the worker thread
    post([task = std::move(task), delay_ms]() mutable {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        task();
    });
}

void AsyncWorker::loop() {
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lk(m_mutex);
            m_cv.wait(lk, [this] {
                return !m_queue.empty() || !m_running;
            });
            if (!m_running && m_queue.empty()) break;
            task = std::move(m_queue.front());
            m_queue.pop();
        }
        task();
    }
}
