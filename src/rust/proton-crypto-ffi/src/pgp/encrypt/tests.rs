use super::EncryptionParameters;
use crate::pgp::keys::PgpKey;

pub(crate) fn enc_params(
    enc_keys: &[*mut PgpKey],
    sign_keys: &[*mut PgpKey],
) -> EncryptionParameters {
    EncryptionParameters {
        profile: 0,
        encryption_keys_len: enc_keys.len(),
        signing_keys_len: sign_keys.len(),
        has_session_key: false,
        has_signing_context: false,
        has_encryption_time: false,
        detached_sig: false,
        detached_sig_encrypted: false,
        utf8: false,
        compress: false,
        encryption_keys: enc_keys.as_ptr().cast(),
        signing_keys: sign_keys.as_ptr().cast(),
        session_key: std::ptr::null_mut(),
        signing_context: std::ptr::null_mut(),
        encryption_time: 0,
        streaming_chunk_size_hint: 0,
        password_len: 0,
        password: std::ptr::null(),
    }
}
