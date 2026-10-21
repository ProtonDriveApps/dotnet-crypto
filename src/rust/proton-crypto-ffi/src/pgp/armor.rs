use super::{BlockType, ForeignWriter, FromId, InteropError, UnsafePtr, catch_error};
use proton_rpgp::armor::{
    armor_message, armor_private_key, armor_public_key, armor_signature, unarmor,
};
use std::io::Write;

impl FromId for BlockType {
    type Output = Result<BlockType, String>;

    fn from_id(value: u8) -> Self::Output {
        match value {
            0 => Ok(BlockType::Message),
            1 => Ok(BlockType::Signature),
            2 => Ok(BlockType::PrivateKey),
            3 => Ok(BlockType::PublicKey),
            _ => Err("unsupported armor block type".to_string()),
        }
    }
}

/// ASCII-armors a binary OpenPGP block and writes the encoded text to the host writer.
///
/// `message`/`message_len` is the binary input; `armor_type` selects the armor header
/// (0 = Message, 1 = Signature, 2 = Private Key, 3 = Public Key; other values error). Trailing
/// newlines are trimmed and the result is streamed to `result_buffer`.
///
/// # Safety
/// `message` must be valid for `message_len` initialized bytes (or null when `message_len == 0`)
/// and `result_buffer` must be a valid `ForeignWriter` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_armor_message(
    message: *const u8,
    message_len: usize,
    armor_type: u8,
    mut result_buffer: ForeignWriter,
) -> InteropError {
    catch_error(|| {
        let message = UnsafePtr::get_slice(message, message_len)?;
        let encoded = match BlockType::from_id(armor_type)? {
            BlockType::Message => armor_message(message),
            BlockType::Signature => armor_signature(message),
            BlockType::PrivateKey => armor_private_key(message),
            BlockType::PublicKey => armor_public_key(message),
            _ => armor_message(message),
        }
        .map_err(|error| error.to_string())?;
        result_buffer
            .write_all(&encoded)
            .map_err(|error| error.to_string())
    })
}

/// Decodes an ASCII-armored OpenPG block and writes the binary contents to the host writer.
///
/// `message`/`message_len` is the armored text input; the armor type is inferred from the input.
/// The decoded bytes are streamed to `result_buffer`.
///
/// # Safety
/// `message` must be valid for `message_len` initialized bytes (or null when `message_len == 0`)
/// and `result_buffer` must be a valid `ForeignWriter` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_unarmor_message(
    message: *const u8,
    message_len: usize,
    mut result_buffer: ForeignWriter,
) -> InteropError {
    catch_error(|| {
        let message = UnsafePtr::get_slice(message, message_len)?;
        let decoded = unarmor(message).map_err(|error| error.to_string())?;
        result_buffer
            .write_all(&decoded)
            .map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests;
