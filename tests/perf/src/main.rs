use std::env;
use std::time::Duration;

use fiber_e2e_tests::{
    run_benchmark_test, run_extreme_native_benchmark, run_integration_test, TestResult,
};

#[tokio::main]
async fn main() -> TestResult<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("🚀 Fiber 高负载压测工具");
        println!("示例:");
        println!("  cargo run --bin run-test benchmark");
        println!("  cargo run --bin run-test integration");
        return Ok(());
    }

    let test_type = &args[1];

    match test_type.as_str() {
        "integration" => {
            println!("🎯 启动集成测试...");
            match run_integration_test().await {
                Ok(_) => println!("All integration tests passed!"),
                Err(e) => {
                    eprintln!("Integration test failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "benchmark" => {
            let duration = args[2].parse::<u64>().unwrap_or(60);
            let workers = args[3].parse::<usize>().unwrap_or(10);

            println!("🎯 启动自定义压测...");
            println!("📊 参数: {}秒, {}个线程", duration, workers);
            run_benchmark_test(Duration::from_secs(duration), workers)?;
        }

        "extreme_benchmark" => {
            let duration = args[2].parse::<u64>().unwrap_or(30);
            let producers = args[3].parse::<usize>().unwrap_or(3);
            let workers = args[4].parse::<usize>().unwrap_or(20);
            let queue_size = args[5].parse::<usize>().unwrap_or(1000);

            println!("🎯 启动自定义压测...");
            println!(
                "📊 参数: {}秒, {}个工作线程, {}个生产者线程, 队列大小{}",
                duration, producers, workers, queue_size
            );
            run_extreme_native_benchmark(
                Duration::from_secs(duration),
                producers,
                workers,
                queue_size,
            )?;
        }

        _ => {
            println!("❌ 未知测试类型: {}", test_type);
            println!("可用类型: integration, benchmark");
        }
    }
    Ok(())
}
