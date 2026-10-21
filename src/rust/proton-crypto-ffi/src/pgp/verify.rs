use super::{
    DataEncoding, ForeignReader, FromId, InteropError, PlaintextResult, Profile, ReaderHandle,
    ReaderJob, UnsafePtr, VerificationContext, Verifier, c_char, catch_error, check_unix_time,
    malloc_bytes, malloc_c_string,
};
use crate::pgp::keys::{PgpKey, key_id_as_u64, owned_public_keys, public_keys_from_keys};
use proton_rpgp::{
    PublicKey, UnixTime, VerificationError, VerificationResult, VerificationResultUtility,
};
use std::io::Write;

fn build_verifier<'a>(
    verification_keys: impl IntoIterator<Item = &'a PublicKey>,
    verification_context: Option<&'a VerificationContext>,
    verification_time: Option<u64>,
) -> Verifier<'a> {
    let mut verifier = Verifier::new(Profile::default()).with_verification_keys(verification_keys);
    if let Some(verification_context) = verification_context {
        verifier = verifier.with_verification_context(verification_context);
    }
    if let Some(verification_time) = verification_time {
        verifier = verifier.at_date(check_unix_time(verification_time));
    }
    verifier
}

#[repr(C)]
pub(crate) struct VerificationParameters {
    pub(crate) keys_len: usize,
    pub(crate) has_verification_time: bool,
    pub(crate) has_verification_context: bool,
    pub(crate) is_utf8: bool,
    pub(crate) keys: *const *const PgpKey,
    pub(crate) verification_context: *const VerificationContext,
    pub(crate) verification_time: u64,
}

#[repr(C)]
pub struct SignatureInfo {
    signature_type: u8,
    creation_time: u64,
    key_id: u64,
    key_fingerprint: *mut u8,
    key_fingerprint_len: usize,
    selected_signature: *mut u8,
    selected_signature_len: usize,
}

#[repr(C)]
pub struct Signatures {
    number_of_signatures: usize,
    all_signatures: *mut u8,
    all_signatures_len: usize,
}

fn status_from_result<T>(result: &Result<T, proton_rpgp::VerificationError>) -> i32 {
    match result {
        Ok(_) => 0,
        Err(VerificationError::NotSigned) => 1,
        Err(VerificationError::NoVerifier(_, _)) => 2,
        Err(VerificationError::Failed(_, _)) => 3,
        Err(VerificationError::BadContext(_, _)) => 4,
        Err(VerificationError::RuntimeError(_)) => 3,
    }
}

/// Verifies a detached OpenPGP signature over `data` and returns a verification-result handle.
///
/// `parameters` supplies the verification keys (from its `keys`/`keys_len` handle array), optional
/// verification context, and optional verification time. `signature`/`signature_len` is the detached
/// signature and `encoding` selects its encoding (0 armored, 1 unarmored, other auto).
/// `out_verification_result` receives a handle to inspect with the `pgp_verification_result_*`
/// functions and release with `pgp_verification_result_destroy`.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized struct; `data`/`signature` must be
/// valid for their lengths (or null when zero); `out_verification_result` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verify_detached(
    parameters: *const VerificationParameters,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    encoding: u8,
    out_verification_result: *mut *mut VerificationResult,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let keys = UnsafePtr::get_handle_slice(params.keys, params.keys_len)?;
        let verification_keys = public_keys_from_keys(keys);
        let verification_context =
            UnsafePtr::maybe_ref(params.verification_context, params.has_verification_context)?;
        let verifier = build_verifier(
            verification_keys,
            verification_context,
            params
                .has_verification_time
                .then_some(params.verification_time),
        );
        let result = verifier.verify_detached(
            UnsafePtr::get_slice(data, data_len)?,
            UnsafePtr::get_slice(signature, signature_len)?,
            encoding,
        );

        *UnsafePtr::ref_mut(out_verification_result)? = UnsafePtr::new_raw(result);
        Ok(())
    })
}

/// Verifies a detached OpenPGP signature over data streamed from a reader and returns a result handle.
///
/// `parameters` supplies the verification keys/context/time; data is read from `input_reader` and
/// verified against the detached `signature`/`signature_len` with the given `encoding` (0 armored,
/// 1 unarmored, other auto). The stream is consumed to completion before the verification result is
/// resolved. `out_verification_result` receives a handle to inspect with the
/// `pgp_verification_result_*` functions and release with `pgp_verification_result_destroy`.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized struct; `input_reader`'s host
/// callbacks must stay valid for the call; `signature` must be valid for `signature_len` (or null
/// when zero); `out_verification_result` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verify_detached_stream(
    parameters: *const VerificationParameters,
    input_reader: ForeignReader,
    signature: *const u8,
    signature_len: usize,
    encoding: u8,
    out_verification_result: *mut *mut VerificationResult,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let keys = UnsafePtr::get_handle_slice(params.keys, params.keys_len)?;
        let verification_keys = public_keys_from_keys(keys);
        let verification_context =
            UnsafePtr::maybe_ref(params.verification_context, params.has_verification_context)?;

        let verifier = build_verifier(
            verification_keys,
            verification_context,
            params
                .has_verification_time
                .then_some(params.verification_time),
        );
        let mut reader = verifier
            .verify_detached_stream(
                input_reader,
                UnsafePtr::get_slice(signature, signature_len)?,
                encoding,
            )
            .map_err(|error| error.to_string())?;
        reader
            .discard_all_data()
            .map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_verification_result)? =
            UnsafePtr::new_raw(reader.verification_result());
        Ok(())
    })
}

/// Decrypts and verifies an inline-signed OpenPGP message, writing plaintext and a result handle.
///
/// `parameters` supplies the decryption/verification keys (from its `keys`/`keys_len` handle array),
/// optional verification context, and optional verification time. `message`/`message_len` is the
/// inline message with the given `encoding` (0 armored, 1 unarmored, other auto). The plaintext is
/// written to the `ForeignWriter` of `result` and the verification-result handle is set on `result`
/// (release with `pgp_verification_result_destroy`).
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized struct; `message` must be valid
/// for `message_len` (or null when zero); `result` must be a valid non-null pointer whose writer
/// callbacks stay valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verify_inline(
    parameters: *const VerificationParameters,
    message: *const u8,
    message_len: usize,
    encoding: u8,
    result: *mut PlaintextResult,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let keys = UnsafePtr::get_handle_slice(params.keys, params.keys_len)?;
        let verification_keys = public_keys_from_keys(keys);
        let verification_context_opt =
            UnsafePtr::maybe_ref(params.verification_context, params.has_verification_context)?;
        let mut verifier = Verifier::default().with_verification_keys(verification_keys);
        if let Some(verification_context) = verification_context_opt {
            verifier = verifier.with_verification_context(verification_context)
        };
        let message = UnsafePtr::get_slice(message, message_len)?;
        let verified = verifier
            .verify(message, encoding)
            .map_err(|error| error.to_string())?;
        let result = UnsafePtr::ref_mut(result)?;
        result
            .plaintext_buffer
            .write_all(&verified.data)
            .map_err(|error| error.to_string())?;

        result.has_verification_result = true;
        result.verification_result = UnsafePtr::new_raw(verified.verification_result);

        Ok(())
    })
}

/// Verifies an inline-signed OpenPGP message as a stream, returning a reader handle.
///
/// `parameters` supplies the verification keys/context; the message is read from `input_reader`
/// with the given `encoding` (0 armored, 1 unarmored, other auto). The message header is consumed
/// synchronously on the calling thread during this call, and each subsequent read on the handle
/// pulls input through `input_reader` on the reading thread. The plaintext stream is exposed
/// via the reader handle written to `out_reader`, which carries the verification result and must
/// be released with its matching reader destroy function.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized struct; `input_reader`'s host
/// callbacks must stay valid until the returned reader handle is destroyed; `out_reader` must be
/// non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verify_inline_stream(
    parameters: *const VerificationParameters,
    input_reader: ForeignReader,
    encoding: u8,
    out_reader: *mut *mut ReaderHandle,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        // Clone the host-borrowed inputs into the handle-owned job: the stream outlives this
        // call, and the host may free its key handles as soon as it returns.
        let job = ReaderJob {
            verification_keys: owned_public_keys(params.keys, params.keys_len)?,
            verification_context: UnsafePtr::maybe_ref(
                params.verification_context,
                params.has_verification_context,
            )?
            .cloned(),
            ..ReaderJob::default()
        };

        let handle = ReaderHandle::try_new(job, move |job| {
            let mut verifier =
                Verifier::default().with_verification_keys(job.verification_keys.iter());
            if let Some(verification_context) = job.verification_context.as_ref() {
                verifier = verifier.with_verification_context(verification_context);
            }
            verifier
                .verify_stream(input_reader, encoding)
                .map_err(|error| error.to_string())
        })?;

        *UnsafePtr::ref_mut(out_reader)? = UnsafePtr::new_raw(handle);
        Ok(())
    })
}

/// Builds a verification-context handle from a context value and requirement settings.
///
/// `value`/`value_len` is the UTF-8 context string; `is_required` marks the context as required;
/// `required_after` is a unix seconds cutoff after which the context is required (0 means none).
/// `out_ctx` receives the new handle, which is released with `pgp_verification_context_destroy`.
///
/// # Safety
/// `value` must be valid UTF-8 for `value_len` bytes (or null when zero); `out_ctx` must be non-null
/// and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_context_new(
    value: *const u8,
    value_len: usize,
    is_required: bool,
    required_after: u64,
    out_ctx: *mut *mut VerificationContext,
) -> InteropError {
    catch_error(|| {
        let value = UnsafePtr::get_string(value, value_len)?;
        let required_after = (required_after != 0).then_some(UnixTime::new(required_after));
        *UnsafePtr::ref_mut(out_ctx)? =
            UnsafePtr::new_raw(VerificationContext::new(value, is_required, required_after));
        Ok(())
    })
}

/// Returns the context value of a verification-context handle as a NUL-terminated C string.
///
/// `ptr` is a live verification-context handle. `out_value` receives a newly allocated C-heap string
/// that the caller MUST free with `interop_memory_free`.
///
/// # Safety
/// `ptr` must be a live verification-context handle; `out_value` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_context_get_value(
    ptr: *const VerificationContext,
    out_value: *mut *mut c_char,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_value)? =
            malloc_c_string(UnsafePtr::as_ref(ptr)?.value.as_bytes()).cast();
        Ok(())
    })
}

/// Writes whether a verification-context handle is marked as required.
///
/// `ptr` is a live verification-context handle; `out_is_required` receives its `is_required` flag.
///
/// # Safety
/// `ptr` must be a live verification-context handle; `out_is_required` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_context_is_required(
    ptr: *const VerificationContext,
    out_is_required: *mut bool,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_is_required)? = UnsafePtr::as_ref(ptr)?.is_required;
        Ok(())
    })
}

/// Writes the unix seconds "required after" cutoff of a verification-context handle (0 = none).
///
/// `ptr` is a live verification-context handle; `out_required_after` receives the cutoff in
/// seconds since the unix epoch.
///
/// # Safety
/// `ptr` must be a live verification-context handle; `out_required_after` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_context_is_required_after(
    ptr: *const VerificationContext,
    out_required_after: *mut u64,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_required_after)? = UnsafePtr::as_ref(ptr)?
            .required_after
            .unwrap_or_default()
            .unix_seconds();
        Ok(())
    })
}

/// Frees a verification-context handle previously created by `pgp_verification_context_new`.
///
/// # Safety
/// `ptr` must be a live verification-context handle and must not be used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_context_destroy(ptr: *mut VerificationContext) {
    UnsafePtr::drop_raw(ptr);
}

fn signature_type_as_u8(signature: &proton_rpgp::pgp::packet::Signature) -> Result<u8, String> {
    signature
        .typ()
        .map(u8::from)
        .ok_or_else(|| "unresolvable signature type".to_string())
}

/// Reports the signature status code of a verification-result handle and any verification error.
///
/// `handle` is a live verification-result handle. `signature_status` receives the status code:
/// 0 = ok/verified, 1 = not signed, 2 = no matching verifier, 3 = verification failed/runtime error,
/// 4 = bad context. The returned `InteropError` carries the verification error message on failure
/// (null message on success).
///
/// # Safety
/// `handle` must be a live verification-result handle; `signature_status` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_result_error(
    handle: *const VerificationResult,
    signature_status: *mut i32,
) -> InteropError {
    let signature_status = UnsafePtr::ref_mut(signature_status);
    let Ok(signature_status) = signature_status else {
        return InteropError::failure("invalid pointer");
    };
    match UnsafePtr::as_ref(handle) {
        Ok(result_ptr) => {
            *signature_status = status_from_result(result_ptr);
            match &result_ptr {
                Ok(_) => InteropError::success(),
                Err(error) => InteropError::failure(error.to_string()),
            }
        }
        Err(message) => InteropError::failure(message),
    }
}

/// Frees a verification-result handle produced by the `pgp_verify_*` functions.
///
/// # Safety
/// `ptr` must be a live verification-result handle and must not be used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_result_destroy(ptr: *mut VerificationResult) {
    UnsafePtr::drop_raw(ptr);
}

/// Fills a `SignatureInfo` with details of the selected signature in a verification result.
///
/// `handle` is a live verification-result handle; `signature_info` is populated with the signature
/// type, creation time, key id, and fingerprint fields. The `selected_signature` buffer is allocated
/// on the C heap and the caller MUST free it with `interop_memory_free`. Fails if the result carries
/// no signature.
///
/// # Safety
/// `handle` must be a live verification-result handle; `signature_info` must be a valid non-null,
/// writable pointer to a `SignatureInfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_result_signature_info(
    handle: *const VerificationResult,
    signature_info: *mut SignatureInfo,
) -> InteropError {
    catch_error(|| {
        let result = VerificationResultUtility::from(UnsafePtr::as_ref(handle)?);
        let information = result
            .verification_information()
            .ok_or_else(|| "no signature found in message".to_string())?;

        if information.signature_creation_time.is_zero() {
            return Err("no signature found in message".to_string());
        }

        let selected_signature = result
            .selected_signature_bytes()
            .map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(signature_info)? = SignatureInfo {
            signature_type: signature_type_as_u8(&information.signature)?,
            creation_time: information.signature_creation_time.unix_seconds(),
            key_id: key_id_as_u64(&information.key_id)?,
            // TODO: Fill in the fingerprint of the verifying key once proton-rpgp exposes it in the
            // verification information, which currently only carries its key ID.
            key_fingerprint: std::ptr::null_mut(),
            key_fingerprint_len: 0,
            selected_signature: malloc_bytes(&selected_signature)?,
            selected_signature_len: selected_signature.len(),
        };

        Ok(())
    })
}

/// Fills a `Signatures` with all signatures (verified plus unverified) of a verification result.
///
/// `handle` is a live verification-result handle; `signatures` receives the total signature count and
/// the concatenated signature bytes. The `all_signatures` buffer is allocated on the C heap and the
/// caller MUST free it with `interop_memory_free`. Fails if the result carries no signature.
///
/// # Safety
/// `handle` must be a live verification-result handle; `signatures` must be a valid non-null, writable
/// pointer to a `Signatures`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_result_all_signatures(
    handle: *const VerificationResult,
    signatures: *mut Signatures,
) -> InteropError {
    catch_error(|| {
        let result = VerificationResultUtility::from(UnsafePtr::as_ref(handle)?);
        let information = result
            .verification_information()
            .ok_or_else(|| "no signature found in message".to_string())?;

        let all_signatures = result
            .all_signature_bytes()
            .map_err(|error| error.to_string())?;
        let number_of_signatures = 1 + information.unverified_signatures.len();

        *UnsafePtr::ref_mut(signatures)? = Signatures {
            number_of_signatures,
            all_signatures: malloc_bytes(&all_signatures)?,
            all_signatures_len: all_signatures.len(),
        };

        Ok(())
    })
}

#[cfg(test)]
pub(crate) mod tests;
