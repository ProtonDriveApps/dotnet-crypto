use super::{
    DataEncoding, ForeignWriter, FromId, HostWorkDispatcherFn, InteropError, PrivateKey, Profile,
    SignatureContext, Signer, UnsafePtr, WriterHandle, catch_error, check_unix_time,
    spawn_write_worker,
};
use crate::pgp::keys::{PgpKey, owned_private_keys, private_keys_vec};
use std::io::Write;
#[repr(C)]
pub(crate) struct SignParameters {
    pub(crate) profile: u8,
    pub(crate) signing_keys_len: usize,
    pub(crate) has_signing_context: bool,
    pub(crate) has_signing_time: bool,
    pub(crate) utf8: bool,
    pub(crate) signing_keys: *const *const PgpKey,
    pub(crate) signing_context: *const SignatureContext,
    pub(crate) signing_time: u64,
}

/// Signs `data` with the keys in `parameters`, writing the signature to `output_writer`.
///
/// `detached` selects a detached signature versus an inline signed message; `encoding` selects the
/// output encoding (0 armored, 1 unarmored, other auto). An optional signing context is taken from
/// `parameters`.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `SignParameters` whose embedded
/// signing-key-handle array and signing-context handle are valid; `data` must be valid for
/// `data_len` bytes (or null when zero); `output_writer` must be a valid host writer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_sign(
    parameters: *const SignParameters,
    data: *const u8,
    data_len: usize,
    encoding: u8,
    detached: bool,
    mut output_writer: ForeignWriter,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let signing_keys = private_keys_vec(params.signing_keys, params.signing_keys_len)?;
        let signing_context =
            UnsafePtr::maybe_ref(params.signing_context, params.has_signing_context)?;
        let signer = SignSettings::from(params).build_signer(signing_keys, signing_context);
        let data = UnsafePtr::get_slice(data, data_len)?;
        let output = if detached {
            signer
                .sign_detached(data, encoding)
                .map_err(|error| error.to_string())?
        } else {
            signer
                .sign(data, encoding)
                .map_err(|error| error.to_string())?
        };
        output_writer
            .write_all(&output)
            .map_err(|error| error.to_string())
    })
}

/// Starts streaming signing, writing a writer handle into `out_writer`.
///
/// A worker reads the data to sign, signs it with the keys/options in `parameters`
/// (`detached` selects detached vs inline; `encoding`: 0 armored, 1 unarmored, other auto), and
/// emits the result to `output_writer`. The worker runs via `work_dispatcher` when provided,
/// otherwise the crate spawns its own thread. The caller writes input through the handle in
/// `out_writer` and owns it, releasing it with the writer destroy fn; `output_writer` must stay
/// valid until that handle is closed.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `SignParameters` whose embedded
/// signing-key-handle array and signing-context handle are valid; `output_writer` must be a valid
/// host writer living until the returned handle is destroyed; `out_writer` must be a valid
/// non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_sign_stream(
    parameters: *const SignParameters,
    output_writer: ForeignWriter,
    encoding: u8,
    detached: bool,
    work_dispatcher: Option<HostWorkDispatcherFn>,
    out_writer: *mut *mut WriterHandle,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let signing_keys = owned_private_keys(params.signing_keys, params.signing_keys_len)?;
        let signing_context =
            UnsafePtr::maybe_ref(params.signing_context, params.has_signing_context)?.cloned();
        let sign_settings = SignSettings::from(params);
        let handle = spawn_write_worker(work_dispatcher, move |reader| {
            let mut output_writer = output_writer;
            let signer = sign_settings.build_signer(signing_keys.iter(), signing_context.as_ref());
            if detached {
                let mut generator = signer
                    .sign_detached_stream(reader, encoding)
                    .map_err(|error| error.to_string())?;
                generator
                    .discard_all_data()
                    .map_err(|error| error.to_string())?;
                let output = generator.finalize().map_err(|error| error.to_string())?;

                output_writer
                    .write_all(&output)
                    .map_err(|error| error.to_string())
            } else {
                signer
                    .sign_stream(reader, encoding, output_writer)
                    .map_err(|error| error.to_string())
            }
        });

        *UnsafePtr::ref_mut(out_writer)? = UnsafePtr::new_raw(handle);
        Ok(())
    })
}

/// Creates a signing-context handle from a string value, writing it into `out_ctx`.
///
/// `value`/`value_len` is the context value (valid UTF-8) and `is_critical` marks the context as
/// critical. The caller owns the returned handle and MUST release it with
/// `pgp_signing_context_new_destroy`.
///
/// # Safety
/// `value` must be valid for `value_len` bytes (or null when zero) and valid UTF-8; `out_ctx` must
/// be a valid non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_signing_context_new(
    value: *const u8,
    value_len: usize,
    is_critical: bool,
    out_ctx: *mut *mut SignatureContext,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_ctx)? = UnsafePtr::new_raw(SignatureContext::new(
            UnsafePtr::get_string(value, value_len)?,
            is_critical,
        ));
        Ok(())
    })
}

/// Releases a signing-context handle created by `pgp_signing_context_new`.
///
/// # Safety
/// `ptr` must be a live signing-context handle that has not already been destroyed; it must not be
/// used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_signing_context_new_destroy(ptr: *mut SignatureContext) {
    UnsafePtr::drop_raw(ptr);
}

#[derive(Clone, Copy)]
struct SignSettings {
    profile: u8,
    has_signing_time: bool,
    utf8: bool,
    signing_time: u64,
}

impl SignSettings {
    fn build_signer<'a>(
        self,
        signing_keys: impl IntoIterator<Item = &'a PrivateKey>,
        signing_context: Option<&'a SignatureContext>,
    ) -> Signer<'a> {
        let profile = Profile::from_id(self.profile);
        let mut signer = Signer::new(profile).with_signing_keys(signing_keys);
        if let Some(signing_context) = signing_context {
            signer = signer.with_signature_context(signing_context);
        }
        if self.has_signing_time {
            signer = signer.at_date(check_unix_time(self.signing_time));
        }
        if self.utf8 {
            signer = signer.as_utf8();
        }
        signer
    }
}

impl From<&SignParameters> for SignSettings {
    fn from(params: &SignParameters) -> Self {
        Self {
            profile: params.profile,
            has_signing_time: params.has_signing_time,
            utf8: params.utf8,
            signing_time: params.signing_time,
        }
    }
}

#[cfg(test)]
mod tests;
