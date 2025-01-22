namespace Proton.Cryptography.Pgp;

public static class PgpPrivateKeyRingExtensions
{
    public static int Decrypt(
        this PgpPrivateKeyRing decryptionKeyRing,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        return PgpDecrypter.Decrypt(input, decryptionKeyRing, output, inputEncoding, timeProviderOverride);
    }
}
