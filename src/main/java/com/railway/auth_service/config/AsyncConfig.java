package com.railway.auth_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Enables async method execution and configures the thread pool.
 *
 * Why @EnableAsync?
 * Without it, @Async annotations are completely ignored.
 * Methods marked @Async will run synchronously — no error,
 * no warning. Silent failure. This is a common Spring gotcha.
 *
 * Why a custom thread pool?
 * Spring's default uses SimpleAsyncTaskExecutor which creates
 * a new thread for every async call — no pooling, no limit.
 * Under load, this creates thousands of threads → OOM crash.
 * A proper pool reuses threads and limits concurrency.
 */
@Slf4j
@Configuration
@EnableAsync
public class AsyncConfig {

  /**
   * Thread pool for async tasks (device info, IP geolocation, etc.)
   *
   * Why these numbers?
   *   corePoolSize=5:  5 threads always ready. Handles normal load.
   *   maxPoolSize=10:  can grow to 10 under burst load.
   *   queueCapacity=50: if all 10 threads busy, queue up to 50 tasks.
   *   Beyond 50 queued → RejectedExecutionException (better than OOM).
   *
   * Why "auth-async-" prefix?
   * Thread names show in logs: "auth-async-1", "auth-async-2".
   * When debugging, you immediately know which pool this thread
   * belongs to. Without prefix, you get "task-1" — meaningless.
   */
  @Bean(name = "authAsyncExecutor")
  public Executor authAsyncExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(5);
    executor.setMaxPoolSize(10);
    executor.setQueueCapacity(50);
    executor.setThreadNamePrefix("auth-async-");
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(30);
    executor.initialize();

    log.info("Auth async executor initialized: core={}, max={}, queue={}",
      executor.getCorePoolSize(), executor.getMaxPoolSize(), executor.getQueueCapacity());

    return executor;
  }
}
