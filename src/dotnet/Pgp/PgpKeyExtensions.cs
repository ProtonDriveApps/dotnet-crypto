namespace Proton.Cryptography.Pgp;

public static class PgpKeyExtensions
{
    public static ArraySegment<byte> ToBytes(this PgpSecretKey secretKey, PgpEncoding encoding = default)
    {
        using var stream = new MemoryStream();

        secretKey.Export(stream, encoding);

        return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
    }

    public static ArraySegment<byte> ToBytes(this PgpPublicKey publicKey, PgpEncoding encoding = default)
    {
        using var stream = new MemoryStream();

        publicKey.Export(stream, encoding);

        return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
    }
}
