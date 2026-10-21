use crate::pgp::keys::{pgp_key_destroy, pgp_key_export};
use crate::tests::*;
use test_case::test_case;

use crate::pgp::armor::{pgp_armor_message, pgp_unarmor_message};

#[test]
fn ffi_pgp_armor_unarmor_round_trip() {
    let binary = data_packet();
    let mut armored = Vec::new();
    unsafe {
        pgp_armor_message(binary.as_ptr(), binary.len(), 0, vec_writer(&mut armored))
            .abort_if_fail("armor");
    }
    assert!(armored.starts_with(b"-----BEGIN PGP MESSAGE-----"));
    let mut decoded = Vec::new();
    unsafe {
        pgp_unarmor_message(armored.as_ptr(), armored.len(), vec_writer(&mut decoded))
            .abort_if_fail("unarmor");
    }
    assert_eq!(decoded, binary);
}

// Armor types: 0 = Message, 1 = Signature, 2 = Private Key, 3 = Public Key.
#[test_case(1, "-----BEGIN PGP SIGNATURE-----" ; "signature")]
#[test_case(2, "-----BEGIN PGP PRIVATE KEY BLOCK-----" ; "private key")]
#[test_case(3, "-----BEGIN PGP PUBLIC KEY BLOCK-----" ; "public key")]
fn ffi_pgp_armor_produces_expected_block(armor_type: u8, header: &str) {
    let binary = match armor_type {
        1 => signature_v4(),
        2 => unsafe {
            let h = priv_key_handle();
            let mut out = Vec::new();
            pgp_key_export(h, false, false, vec_writer(&mut out)).abort_if_fail("export private");
            pgp_key_destroy(h);
            out
        },
        _ => unsafe {
            let h = pub_key_handle();
            let mut out = Vec::new();
            pgp_key_export(h, true, false, vec_writer(&mut out)).abort_if_fail("export public");
            pgp_key_destroy(h);
            out
        },
    };

    let mut armored = Vec::new();
    unsafe {
        pgp_armor_message(
            binary.as_ptr(),
            binary.len(),
            armor_type,
            vec_writer(&mut armored),
        )
        .abort_if_fail("armor");
    }
    assert!(armored.starts_with(header.as_bytes()));
}

#[test]
fn ffi_pgp_armor_invalid_type_returns_error() {
    let binary = data_packet();
    let mut armored = Vec::new();
    unsafe {
        let err = pgp_armor_message(binary.as_ptr(), binary.len(), 9, vec_writer(&mut armored));
        assert!(!err.is_success(), "unknown armor type must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
    }
}
