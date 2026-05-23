namespace Proton.Cryptography.Pgp;

public static class EncryptionSecretsExtensions
{
    extension<T>(T encryptionSecretsSource)
        where T : IEncryptionSecretsSource
    {
        public ArraySegment<byte> Encrypt(PgpSessionKey sessionKey, out Span<byte> outputKeyPacket)
        {
            throw new NotImplementedException();
        }

        public int Encrypt(
            ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> output,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.Encrypt(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                output,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public int EncryptAndSign(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            ReadOnlySpan<byte> output,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.EncryptAndSign(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                output,
                signingKeyRing,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public int EncryptAndSign(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            ReadOnlySpan<byte> output,
            ReadOnlySpan<byte> signatureOutput,
            out int signatureLength,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> Encrypt(
            ReadOnlySpan<byte> input,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.Encrypt(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> EncryptAndSign(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.EncryptAndSign(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> EncryptAndSign(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            out ArraySegment<byte> signature,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public void EncryptToStream(
            ReadOnlySpan<byte> input,
            Stream outputStream,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            PgpEncrypter.EncryptToStream(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                outputStream,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public void EncryptAndSignToStream(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            Stream outputStream,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            PgpEncrypter.EncryptAndSignToStream(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                outputStream,
                signingKeyRing,
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public void EncryptAndSignToStreams(
            ReadOnlySpan<byte> input,
            PgpPrivateKeyRing signingKeyRing,
            Stream outputStream,
            Stream signatureOutputStream,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> EncryptText(
            string input,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            Encoding? textEncoding = null,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.EncryptText(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                outputEncoding,
                outputCompression,
                textEncoding,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> EncryptAndSignText(
            string input,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            Encoding? textEncoding = null,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncrypter.EncryptAndSignText(
                input,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                outputEncoding,
                outputCompression,
                textEncoding,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public ArraySegment<byte> EncryptAndSignText(
            string input,
            PgpPrivateKeyRing signingKeyRing,
            out ArraySegment<byte> signature,
            PgpEncoding outputEncoding = default,
            PgpCompression outputCompression = default,
            EncryptionState signatureEncryptionState = default,
            Encoding? textEncoding = null,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingStream(
            Stream messageOutputStream,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.Open(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingReadStream(
            Stream messageOutputStream,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.OpenRead(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingAndSigningStream(
            Stream messageOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.Open(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingAndSigningReadStream(
            Stream messageOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.OpenRead(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingAndSigningStream(
            Stream messageOutputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenEncryptingAndSigningReadStream(
            Stream messageOutputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenSplitEncryptingStream(
            Stream messageOutputStream,
            Stream keyPacketsOutputStream,
            PgpCompression messageCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.OpenSplit(
                messageOutputStream,
                keyPacketsOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                messageCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenSplitEncryptingReadStream(
            Stream messageOutputStream,
            Stream keyPacketsOutputStream,
            PgpCompression messageCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingStream.OpenSplitRead(
                messageOutputStream,
                keyPacketsOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                messageCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenSplitEncryptingStream(
            Stream messageOutputStream,
            Stream keyPacketsOutputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingStream OpenSplitEncryptingReadStream(
            Stream messageOutputStream,
            Stream keyPacketsOutputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
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
                aeadStreamingChunkLength,
                timeProviderOverride);
        }
    }
}
