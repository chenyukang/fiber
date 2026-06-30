use crate::cch::{
    actions::send_outgoing_payment::SendLightningOutgoingPaymentExecutor,
    trackers::CchTrackingEvent,
};
use fiber_types::{payment::PaymentStatus, Hash256};

fn test_payment_hash(value: u8) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0] = value;
    Hash256::from(bytes)
}

#[test]
fn test_lnd_already_paid_unknown_error_maps_to_inflight() {
    let payment_hash = test_payment_hash(1);
    let status = tonic::Status::unknown("invoice is already paid");

    let event =
        SendLightningOutgoingPaymentExecutor::map_lnd_send_payment_error(payment_hash, &status)
            .expect("already-paid errors should keep tracking the payment");

    let CchTrackingEvent::PaymentChanged {
        payment_hash: event_hash,
        payment_preimage,
        status,
        failure_reason,
    } = event
    else {
        panic!("expected payment changed event");
    };

    assert_eq!(event_hash, payment_hash);
    assert_eq!(status, PaymentStatus::Inflight);
    assert_eq!(payment_preimage, None);
    assert_eq!(failure_reason, None);
}

#[test]
fn test_lnd_already_exists_error_maps_to_inflight() {
    let payment_hash = test_payment_hash(2);
    let status = tonic::Status::already_exists("payment already in flight");

    let event =
        SendLightningOutgoingPaymentExecutor::map_lnd_send_payment_error(payment_hash, &status)
            .expect("already-existing payments should keep tracking the payment");

    let CchTrackingEvent::PaymentChanged {
        status,
        failure_reason,
        ..
    } = event
    else {
        panic!("expected payment changed event");
    };

    assert_eq!(status, PaymentStatus::Inflight);
    assert_eq!(failure_reason, None);
}

#[test]
fn test_lnd_permanent_error_still_maps_to_failed() {
    let payment_hash = test_payment_hash(3);
    let status = tonic::Status::unknown("unable to find a path to destination");

    let event =
        SendLightningOutgoingPaymentExecutor::map_lnd_send_payment_error(payment_hash, &status)
            .expect("permanent errors should be final failures");

    let CchTrackingEvent::PaymentChanged {
        status,
        failure_reason,
        ..
    } = event
    else {
        panic!("expected payment changed event");
    };

    assert_eq!(status, PaymentStatus::Failed);
    assert!(failure_reason.is_some());
}

#[test]
fn test_lnd_transient_error_is_not_mapped_to_final_event() {
    let payment_hash = test_payment_hash(4);
    let status = tonic::Status::unavailable("lnd unavailable");

    let event =
        SendLightningOutgoingPaymentExecutor::map_lnd_send_payment_error(payment_hash, &status);

    assert!(event.is_none());
}
