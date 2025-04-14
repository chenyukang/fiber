for i in {1..10}; do
  TEST_TEMP_RETAIN=1 RUST_THREAD_PANIC_ABORT=1 RUST_BACKTRACE=full  cargo test test_send_payment_remove_tlc_with_preimage_will_retry -- --nocapture || { echo "Command failed on iteration $i"; exit 1; }
done