namespace Proton.Cryptography.Pgp;

public static class VerificationKeyRingSourceExtensions
{
    public static PgpVerificationResult Verify<T>(
        this T verificationKeyRingSource,
        ReadOnlySpan<byte> message,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IVerificationKeyRingSource
    {
        return PgpVerifier.Verify(message, verificationKeyRingSource.VerificationKeyRing, encoding);
    }

    public static PgpVerificationResult Verify<T>(
        this T verificationKeyRingSource,
        Stream messageStream,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IVerificationKeyRingSource
    {
        return PgpVerifier.Verify(messageStream, verificationKeyRingSource.VerificationKeyRing, encoding);
    }

    public static PgpVerificationResult Verify<T>(
        this T verificationKeyRingSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IVerificationKeyRingSource
    {
        return PgpVerifier.Verify(input, signature, verificationKeyRingSource.VerificationKeyRing, encoding);
    }

    public static PgpVerificationResult Verify<T>(
        this T verificationKeyRingSource,
        Stream inputStream,
        ReadOnlySpan<byte> signature,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IVerificationKeyRingSource
    {
        return PgpVerifier.Verify(inputStream, signature, verificationKeyRingSource.VerificationKeyRing, encoding);
    }
}
