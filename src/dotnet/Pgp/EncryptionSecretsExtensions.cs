namespace Proton.Cryptography.Pgp;

public static class EncryptionSecretsExtensions
{
    public static ArraySegment<byte> Encrypt<T>(this T encryptionSecretsSource, PgpSessionKey sessionKey, out Span<byte> outputKeyPacket)
        where T : IEncryptionSecretsSource
    {
        throw new NotImplementedException();
    }

    public static int Encrypt<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> output,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.Encrypt(input, encryptionSecretsSource.EncryptionSecrets, output, outputEncoding, outputCompression, profile, timeProviderOverride);
    }

    public static int EncryptAndSign<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        ReadOnlySpan<byte> output,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSign(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            output,
            signingKeyRing,
            outputEncoding,
            outputCompression,
            profile,
            timeProviderOverride);
    }

    public static int EncryptAndSign<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        ReadOnlySpan<byte> output,
        ReadOnlySpan<byte> signatureOutput,
        out int signatureLength,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSign(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            output,
            signingKeyRing,
            signatureOutput,
            out signatureLength,
            outputEncoding,
            outputCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static ArraySegment<byte> Encrypt<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.Encrypt(input, encryptionSecretsSource.EncryptionSecrets, outputEncoding, outputCompression, profile, timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptAndSign<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSign(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            outputEncoding,
            outputCompression,
            profile,
            timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptAndSign<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        out ArraySegment<byte> signature,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSign(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            out signature,
            outputEncoding,
            outputCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static void EncryptToStream<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        PgpEncrypter.EncryptToStream(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            outputStream,
            outputEncoding,
            outputCompression,
            profile,
            timeProviderOverride);
    }

    public static void EncryptAndSignToStream<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        PgpEncrypter.EncryptAndSignToStream(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            outputStream,
            signingKeyRing,
            outputEncoding,
            outputCompression,
            profile,
            timeProviderOverride);
    }

    public static void EncryptAndSignToStreams<T>(
        this T encryptionSecretsSource,
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        Stream signatureOutputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        PgpEncrypter.EncryptAndSignToStreams(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            outputStream,
            signingKeyRing,
            signatureOutputStream,
            outputEncoding,
            outputCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptText<T>(
        this T encryptionSecretsSource,
        string input,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        Encoding? textEncoding = null,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptText(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            outputEncoding,
            outputCompression,
            textEncoding,
            profile,
            timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptAndSignText<T>(
        this T encryptionSecretsSource,
        string input,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        Encoding? textEncoding = null,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSignText(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            outputEncoding,
            outputCompression,
            textEncoding,
            profile,
            timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptAndSignText<T>(
        this T encryptionSecretsSource,
        string input,
        PgpPrivateKeyRing signingKeyRing,
        out ArraySegment<byte> signature,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        Encoding? textEncoding = null,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncrypter.EncryptAndSignText(
            input,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            out signature,
            outputEncoding,
            outputCompression,
            signatureEncryptionState,
            textEncoding,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.Open(messageOutputStream, encryptionSecretsSource.EncryptionSecrets, encoding, compression, profile, timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingReadStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenRead(
            messageOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            encoding,
            compression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingAndSigningStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.Open(
            messageOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingAndSigningReadStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenRead(
            messageOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingAndSigningStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream signatureOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.Open(
            messageOutputStream,
            signatureOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            encoding,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenEncryptingAndSigningReadStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream signatureOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenRead(
            messageOutputStream,
            signatureOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            encoding,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplitEncryptingStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenSplit(
            messageOutputStream,
            keyPacketsOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            messageCompression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplitEncryptingReadStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenSplitRead(
            messageOutputStream,
            keyPacketsOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            messageCompression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplitEncryptingStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenSplit(
            messageOutputStream,
            keyPacketsOutputStream,
            signatureOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplitEncryptingReadStream<T>(
        this T encryptionSecretsSource,
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
        where T : IEncryptionSecretsSource
    {
        return PgpEncryptingStream.OpenSplitRead(
            messageOutputStream,
            keyPacketsOutputStream,
            signatureOutputStream,
            encryptionSecretsSource.EncryptionSecrets,
            signingKeyRing,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }
}
