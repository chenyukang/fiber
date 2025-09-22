use std::time::Duration;
use std::env;

use fiber_e2e_tests::{run_extreme_native_benchmark, run_native_thread_benchmark};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("🚀 Fiber 高负载压测工具");
        println!("用法: cargo run --bin benchmark <test_type>");
        println!();
        println!("可用测试类型:");
        println!("  extreme    - 极限队列压测 (生产者-消费者模式)");
        println!("  standard   - 标准原生线程压测");
        println!("  custom     - 自定义参数压测");
        println!();
        println!("示例:");
        println!("  cargo run --bin benchmark extreme");
        println!("  cargo run --bin benchmark standard");
        return Ok(());
    }

    let test_type = &args[1];

    match test_type.as_str() {
        "extreme" => {
            println!("🔥 启动极限队列压测...");
            println!("📊 参数: 30秒, 3个工作线程, 20个生产者线程, 队列大小1000");
            run_extreme_native_benchmark(Duration::from_secs(30), 3, 20, 1000)?;
        }

        "standard" => {
            println!("⚡ 启动标准原生线程压测...");
            println!("📊 参数: 30秒, 6个线程, 每个线程50并发");
            run_native_thread_benchmark(Duration::from_secs(30), 6, 50)?;
        }

        "custom" => {
            if args.len() < 6 {
                println!("❌ 自定义模式需要更多参数:");
                println!("  cargo run --bin benchmark custom <duration_secs> <worker_threads> <producer_threads> <queue_size>");
                println!("示例: cargo run --bin benchmark custom 60 4 10 2000");
                return Ok(());
            }

            let duration = args[2].parse::<u64>().unwrap_or(30);
            let workers = args[3].parse::<usize>().unwrap_or(3);
            let producers = args[4].parse::<usize>().unwrap_or(20);
            let queue_size = args[5].parse::<usize>().unwrap_or(1000);

            println!("🎯 启动自定义压测...");
            println!("📊 参数: {}秒, {}个工作线程, {}个生产者线程, 队列大小{}",
                duration, workers, producers, queue_size);
            run_extreme_native_benchmark(Duration::from_secs(duration), workers, producers, queue_size)?;
        }

        _ => {
            println!("❌ 未知测试类型: {}", test_type);
            println!("可用类型: extreme, standard, custom");
        }
    }

    Ok(())
}
