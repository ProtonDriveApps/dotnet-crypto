namespace Proton.Cryptography.Pgp;

public static class EncryptionKeyRingSourceExtensions
{
    public static ArraySegment<byte> EncryptSessionKey<T>(
        this T encryptionKeyRingSource,
        PgpSessionKey sessionKey,
        PgpProfile pgpProfile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionKeyRingSource
    {
        var keyPacketStream = MemoryProvider.GetMemoryStreamForKeyPackets(encryptionKeyRingSource.EncryptionKeyRing.Count);

        sessionKey.ToKeyPackets(encryptionKeyRingSource.EncryptionKeyRing, keyPacketStream, pgpProfile, timeProviderOverride);

        return keyPacketStream.TryGetBuffer(out var arraySegment) ? arraySegment : keyPacketStream.ToArray();
    }

    public static void EncryptSessionKeyToStream<T>(
        this T encryptionKeyRingSource,
        PgpSessionKey sessionKey,
        Stream keyPacketOutputStream,
        PgpProfile pgpProfile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionKeyRingSource
    {
        sessionKey.ToKeyPackets(encryptionKeyRingSource.EncryptionKeyRing, keyPacketOutputStream, pgpProfile, timeProviderOverride);
    }
}
