use crate::pgp::keys::PgpKey;
use crate::pgp::sign::SignParameters;

pub(crate) fn sign_params_for(sign_keys: &[*mut PgpKey]) -> SignParameters {
    SignParameters {
        profile: 0,
        signing_keys_len: sign_keys.len(),
        has_signing_context: false,
        has_signing_time: false,
        utf8: false,
        signing_keys: sign_keys.as_ptr().cast(),
        signing_context: std::ptr::null_mut(),
        signing_time: 0,
    }
}
