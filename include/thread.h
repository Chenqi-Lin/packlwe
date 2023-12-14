/*
cheetah thread head file
*/

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "common.h"

namespace threadset {
class ThreadPool {
 public:
  ThreadPool(size_t);
  template <class F, class... Args>
      auto enqueue(F&& f, Args&&... args)
      -> std::future<typename std::result_of<F(Args...)>::type>;
  ~ThreadPool();

  inline size_t pool_size() const { return workers.size(); }
  inline size_t tasks_num() const { return finish_flag; }
 private:
  // need to keep track of threads so we can join them
  std::vector<std::thread> workers;
  // the task queue
  std::queue<std::function<void()> > tasks;

  // synchronization
  std::mutex queue_mutex;
  std::condition_variable condition;
  bool stop;

  // 初始化为0，lanuchwork后，有一个任务则被加一，完成后减一
  int finish_flag;
};

// the constructor just launches some amount of workers
// 每个thread不断循环，从task这个vector中取出任务
// for循环后直接跟了一个函数（emplace_back），故不需要大括号
inline ThreadPool::ThreadPool(size_t threads) : stop(false) {
  finish_flag=0;
  for (size_t i = 0; i < threads; ++i)
    workers.emplace_back([this] {
      for (;;) {
        std::function<void()> task;

        {
          // 互斥锁，唤醒后只有独占的线程可以执行这个function，执行完后释放锁
          std::unique_lock<std::mutex> lock(this->queue_mutex);
          this->condition.wait(
              lock, [this] { return this->stop || !this->tasks.empty(); });
          if (this->stop && this->tasks.empty()) return;
          task = std::move(this->tasks.front());
          this->tasks.pop();
        }

        task();
        finish_flag-=1;
      }
    });
}

// add new work item to the pool
template <class F, class... Args>
    auto ThreadPool::enqueue(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type> {
  using return_type = typename std::result_of<F(Args...)>::type;

  auto task = std::make_shared<std::packaged_task<return_type()> >(
      std::bind(std::forward<F>(f), std::forward<Args>(args)...));

  std::future<return_type> res = task->get_future();
  {
    std::unique_lock<std::mutex> lock(queue_mutex);

    // don't allow enqueueing after stopping the pool
    if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");
    // 向tasks这个vector中塞入task
    tasks.emplace([task]() { (*task)(); });
    finish_flag+=1;
  }
  condition.notify_one();
  return res;
}

// the destructor joins all threads
inline ThreadPool::~ThreadPool() {
  {
    std::unique_lock<std::mutex> lock(queue_mutex);
    stop = true;
  }
  condition.notify_all();
  for (std::thread& worker : workers) worker.join();
}

}
#endif
