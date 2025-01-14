namespace Proton.Cryptography.Pgp;

public static class PgpKeyExtensions
{
    public static ArraySegment<byte> ToBytes(this PgpPrivateKey privateKey, PgpEncoding encoding = default)
    {
        using var stream = new MemoryStream();

        privateKey.Export(stream, encoding);

        return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
    }

    public static ArraySegment<byte> ToBytes(this PgpPublicKey publicKey, PgpEncoding encoding = default)
    {
        using var stream = new MemoryStream();

        publicKey.Export(stream, encoding);

        return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
    }
}
