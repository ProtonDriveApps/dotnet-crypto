namespace Proton.Cryptography.Pgp;

public static class DecryptionKeyRingSourceExtensions
{
    public static PgpSessionKey DecryptSessionKey<T>(this T decryptionKeyRingSource, ReadOnlySpan<byte> keyPackets)
        where T : IDecryptionKeyRingSource
    {
        return PgpDecrypter.DecryptSessionKey(keyPackets, decryptionKeyRingSource.DecryptionKeyRing);
    }
}
