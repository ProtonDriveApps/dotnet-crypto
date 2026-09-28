namespace Proton.Cryptography;

public static class AesGcmDecrypter
{
    public const int NonceLength = 12;
    public const int TagLength = 16;

    public static int GetPlaintextLength(int blobLength)
    {
        if (blobLength < NonceLength + TagLength)
        {
            throw new CryptographicException("The blob is too short to contain a nonce and a tag");
        }

        return blobLength - NonceLength - TagLength;
    }

    /// <summary>
    /// Decrypts the blob into the provided destination buffer if the authentication tag can be validated.
    /// </summary>
    /// <param name="key">The secret key to use for decryption.</param>
    /// <param name="blob">The encrypted blob, laid out as <c>nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)</c>.</param>
    /// <param name="destination">The byte span to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    /// <exception cref="ArgumentException">
    /// The <paramref name="destination"/> buffer is too small to hold the decrypted contents.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The <paramref name="key"/> length is other than 16, 24, or 32 bytes (128, 192, or 256 bits). <para>-or-</para>
    /// The <paramref name="blob"/> is too short to contain a nonce and a tag. <para>-or-</para>
    /// The tag value could not be verified, or the decryption operation otherwise failed.
    /// </exception>
    public static int Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> blob,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData)
    {
        var plaintextLength = GetPlaintextLength(blob.Length);

        if (destination.Length < plaintextLength)
        {
            throw new ArgumentException("The destination is too small", nameof(destination));
        }

        using var aes = new AesGcm(key, TagLength);

        aes.Decrypt(
            nonce: blob[..NonceLength],
            ciphertext: blob[NonceLength..^TagLength],
            tag: blob[^TagLength..],
            plaintext: destination[..plaintextLength],
            associatedData);

        return plaintextLength;
    }
}
