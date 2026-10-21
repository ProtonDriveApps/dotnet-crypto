use crate::pgp::message::{pgp_message_destroy, pgp_message_key_packet_split, pgp_message_new};
use crate::tests::*;

#[test]
fn ffi_pgp_message_new_key_packet_split_and_destroy() {
    let msg = KEY_BASED_ARMORED_UNSIGNED_MESSAGE.as_bytes();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_message_new(msg.as_ptr(), msg.len(), true, &mut h).abort_if_fail("message_new");
        let mut count = 0usize;
        pgp_message_key_packet_split(h, &mut count).abort_if_fail("key_packet_split");
        assert!(count > 0);
        pgp_message_destroy(h);
    }
}

#[test]
fn ffi_pgp_message_new_binary_key_packet_split() {
    let mut msg = key_packet_v4();
    let key_packet_len = msg.len();
    msg.extend_from_slice(&data_packet());
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_message_new(msg.as_ptr(), msg.len(), false, &mut h).abort_if_fail("binary message_new");
        let mut count = 0usize;
        pgp_message_key_packet_split(h, &mut count).abort_if_fail("key_packet_split");
        assert_eq!(count, key_packet_len);
        pgp_message_destroy(h);
    }
}
