namespace Proton.Cryptography.Pgp;

public static class DecryptionSecretsExtensions
{
    public static int DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            verificationKeyRing,
            output,
            out verificationResult,
            inputEncoding,
            timeProviderOverride);
    }

    public static int DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            signature,
            verificationKeyRing,
            output,
            out verificationResult,
            inputEncoding,
            signatureEncoding,
            signatureEncryptionState,
            timeProviderOverride);
    }

    public static void Decrypt<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        Stream outputStream,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        PgpDecrypter.Decrypt(input, decryptionSecretsSource.DecryptionSecrets, outputStream, inputEncoding, timeProviderOverride);
    }

    public static void DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpKeyRing verificationKeyRing,
        Stream outputStream,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            verificationKeyRing,
            outputStream,
            out verificationResult,
            inputEncoding,
            timeProviderOverride);
    }

    public static void DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        Stream outputStream,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            signature,
            verificationKeyRing,
            outputStream,
            out verificationResult,
            inputEncoding,
            signatureEncoding,
            signatureEncryptionState,
            timeProviderOverride);
    }

    public static ArraySegment<byte> Decrypt<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.Decrypt(input, decryptionSecretsSource.DecryptionSecrets, inputEncoding, timeProviderOverride);
    }

    public static ArraySegment<byte> DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            timeProviderOverride);
    }

    public static ArraySegment<byte> DecryptAndVerify<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerify(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            signature,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            signatureEncoding,
            signatureEncryptionState,
            timeProviderOverride);
    }

    public static string DecryptText<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptText(input, decryptionSecretsSource.DecryptionSecrets, inputEncoding, textEncoding, timeProviderOverride);
    }

    public static string DecryptAndVerifyText<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerifyText(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            textEncoding,
            timeProviderOverride);
    }

    public static string DecryptAndVerifyText<T>(
        this T decryptionSecretsSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecrypter.DecryptAndVerifyText(
            input,
            decryptionSecretsSource.DecryptionSecrets,
            signature,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            textEncoding,
            timeProviderOverride);
    }

    public static PgpDecryptingStream OpenDecryptingStream<T>(
        this T decryptionSecretsSource,
        Stream inputStream,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecryptingStream.Open(inputStream, decryptionSecretsSource.DecryptionSecrets, inputEncoding, timeProviderOverride);
    }

    public static PgpDecryptingStream OpenDecryptingAndVerifyingStream<T>(
        this T decryptionSecretsSource,
        Stream inputStream,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecryptingStream.Open(inputStream, decryptionSecretsSource.DecryptionSecrets, verificationKeyRing, inputEncoding, timeProviderOverride);
    }

    public static PgpDecryptingStream OpenDecryptingAndVerifyingStream<T>(
        this T decryptionSecretsSource,
        Stream inputStream,
        ReadOnlyMemory<byte> signature,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
        where T : IDecryptionSecretsSource
    {
        return PgpDecryptingStream.Open(
            inputStream,
            decryptionSecretsSource.DecryptionSecrets,
            signature,
            verificationKeyRing,
            inputEncoding,
            signatureEncoding,
            signatureEncryptionState,
            timeProviderOverride);
    }
}
