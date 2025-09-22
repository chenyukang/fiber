use std::thread;
use std::time::Duration;

fn main() {
    println!("🎯 Binary 模式 - 真正的多线程演示");
    println!("📱 请在Activity Monitor中查看 PID: {}", std::process::id());

    let thread_count = 8;

    let handles: Vec<_> = (0..thread_count)
        .map(|i| {
            thread::spawn(move || {
                println!("🚀 线程 {} 启动，线程ID: {:?}", i, thread::current().id());

                // 做一些CPU密集型工作，让线程保持活跃
                for cycle in 0..100 {
                    let mut sum = 0u64;
                    for j in 0..1000000 {
                        sum = sum.wrapping_add(j);
                    }

                    if cycle % 20 == 0 {
                        println!("线程 {} - 循环 {} (sum: {})", i, cycle, sum);
                    }

                    thread::sleep(Duration::from_millis(200));
                }

                println!("🏁 线程 {} 完成", i);
            })
        })
        .collect();

    println!("✅ 已创建 {} 个线程", thread_count);
    println!("⏰ 运行中... (观察Activity Monitor)");

    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }

    println!("🎉 所有线程完成！");
}
