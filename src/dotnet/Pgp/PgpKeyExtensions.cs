namespace Proton.Cryptography.Pgp;

public static class PgpKeyExtensions
{
    extension(PgpSecretKey secretKey)
    {
        public ArraySegment<byte> ToBytes(PgpEncoding encoding = default)
        {
            using var stream = new MemoryStream();

            secretKey.Export(stream, encoding);

            return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
        }
    }

    extension(PgpPrivateKey privateKey)
    {
        public ArraySegment<byte> ToBytes(PgpEncoding encoding = default)
        {
            using var stream = new MemoryStream();

            privateKey.Export(stream, encoding);

            return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
        }
    }

    extension(PgpPublicKey publicKey)
    {
        public ArraySegment<byte> ToBytes(PgpEncoding encoding = default)
        {
            using var stream = new MemoryStream();

            publicKey.Export(stream, encoding);

            return stream.TryGetBuffer(out var buffer) ? buffer : stream.ToArray();
        }
    }
}
