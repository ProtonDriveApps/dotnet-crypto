namespace Proton.Cryptography.Pgp;

public static class SigningKeyRingSourceExtensions
{
    public static ArraySegment<byte> Sign<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        PgpEncoding outputEncoding = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.Sign(inputStream, signingKeyRingSource.SigningKeyRing, outputEncoding);
    }

    public static Task<ArraySegment<byte>> SignAsync<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.SignAsync(inputStream, signingKeyRingSource.SigningKeyRing, cancellationToken, outputEncoding);
    }

    public static ArraySegment<byte> Sign<T>(
        this T signingKeyRingSource,
        ReadOnlySpan<byte> input,
        PgpEncoding outputEncoding = default,
        SigningOutputType signingOutputType = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.Sign(input, signingKeyRingSource.SigningKeyRing, outputEncoding, signingOutputType);
    }

    public static int Sign<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        Span<byte> output,
        PgpEncoding outputEncoding = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.Sign(inputStream, signingKeyRingSource.SigningKeyRing, output, outputEncoding);
    }

    public static Task<int> SignAsync<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        Memory<byte> signatureOutput,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.SignAsync(inputStream, signingKeyRingSource.SigningKeyRing, signatureOutput, cancellationToken, outputEncoding);
    }

    public static int Sign<T>(
        this T signingKeyRingSource,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.Sign(input, signingKeyRingSource.SigningKeyRing, output, outputEncoding, outputType);
    }

    public static void Sign<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default)
        where T : ISigningKeyRingSource
    {
        PgpSigner.Sign(inputStream, signingKeyRingSource.SigningKeyRing, outputStream, outputEncoding, outputType);
    }

    public static Task SignAsync<T>(
        this T signingKeyRingSource,
        Stream inputStream,
        Stream outputStream,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigner.SignAsync(inputStream, signingKeyRingSource.SigningKeyRing, outputStream, cancellationToken, outputEncoding, outputType);
    }

    public static void Sign<T>(
        this T signingKeyRingSource,
        ReadOnlySpan<byte> input,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default)
        where T : ISigningKeyRingSource
    {
        PgpSigner.Sign(input, signingKeyRingSource.SigningKeyRing, outputStream, outputEncoding, outputType);
    }

    public static PgpSigningStream OpenSigningStream<T>(
        this T signingKeyRingSource,
        Stream outputStream,
        PgpEncoding encoding = default,
        SigningOutputType outputType = default)
        where T : ISigningKeyRingSource
    {
        return PgpSigningStream.Open(outputStream, signingKeyRingSource.SigningKeyRing, encoding, outputType);
    }
}
