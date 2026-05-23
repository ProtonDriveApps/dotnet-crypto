namespace Proton.Cryptography.Pgp;

public static class DecryptionKeyRingSourceExtensions
{
    extension<T>(T decryptionKeyRingSource)
        where T : IDecryptionKeyRingSource
    {
        public PgpSessionKey DecryptSessionKey(ReadOnlySpan<byte> keyPackets)
        {
            return PgpDecrypter.DecryptSessionKey(keyPackets, decryptionKeyRingSource.DecryptionKeyRing);
        }
    }
}
