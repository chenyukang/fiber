#!/bin/bash
set -euo pipefail

echo "🚀 Fiber 压力测试套件"
echo "====================="

function run_test() {
    local test_name=$1
    local description=$2

    echo
    echo "🔥 运行 $description..."
    echo "测试名称: $test_name"
    echo "开始时间: $(date)"
    echo "----------------------------------------"

    if cargo test "$test_name" -- --ignored --nocapture; then
        echo "✅ $description 完成"
    else
        echo "❌ $description 失败"
        return 1
    fi

    echo "结束时间: $(date)"
    echo "----------------------------------------"
}

# 检查参数
if [ $# -eq 0 ]; then
    echo "用法: $0 [test_type]"
    echo
    echo "可用测试类型:"
    echo "  quick        - 快速测试（10秒）"
    echo "  standard     - 标准测试（30-60秒）"
    echo "  extreme      - 极限测试（长时间，高负载）"
    echo "  tokio        - Tokio异步测试"
    echo "  native       - 原生线程测试"
    echo "  all          - 运行所有测试"
    exit 1
fi

TEST_TYPE=$1

case "$TEST_TYPE" in
    "quick")
        echo "🏃‍♂️ 运行快速测试..."
        run_test "test_quick_native_benchmark" "快速原生线程压测"
        ;;

    "standard")
        echo "📊 运行标准测试..."
        run_test "test_native_thread_benchmark" "标准原生线程压测"
        run_test "test_short_benchmark" "标准Tokio压测"
        ;;

    "extreme")
        echo "⚡ 运行极限测试..."
        run_test "test_extreme_native_benchmark" "极限原生线程压测"
        run_test "test_extreme_native_queue_benchmark" "极限队列压测"
        ;;

    "tokio")
        echo "🌊 运行Tokio异步测试..."
        run_test "test_short_benchmark" "短期Tokio压测"
        run_test "test_benchmark" "长期Tokio压测"
        ;;

    "native")
        echo "🔧 运行原生线程测试..."
        run_test "test_quick_native_benchmark" "快速原生测试"
        run_test "test_native_thread_benchmark" "标准原生测试"
        run_test "test_extreme_native_benchmark" "极限原生测试"
        ;;

    "all")
        echo "🎯 运行所有测试..."
        run_test "test_quick_native_benchmark" "快速原生线程压测"
        run_test "test_native_thread_benchmark" "标准原生线程压测"
        run_test "test_short_benchmark" "短期Tokio压测"
        run_test "test_extreme_native_benchmark" "极限原生线程压测"
        run_test "test_extreme_native_queue_benchmark" "极限队列压测"
        ;;

    *)
        echo "❌ 未知测试类型: $TEST_TYPE"
        echo "请使用: quick, standard, extreme, tokio, native, 或 all"
        exit 1
        ;;
esac

echo
echo "🎉 所有测试完成!"
echo "完成时间: $(date)"
