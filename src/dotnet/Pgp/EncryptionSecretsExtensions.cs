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

        public PgpEncryptingWriteStream OpenEncryptingWriteStream(
            Stream messageOutputStream,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingWriteStream.Open(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingReadStream OpenEncryptingReadStream(
            Stream plainDataInputStream,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingReadStream.Open(
                plainDataInputStream,
                encryptionSecretsSource.EncryptionSecrets,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingWriteStream OpenEncryptingAndSigningWriteStream(
            Stream messageOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingWriteStream.Open(
                messageOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingReadStream OpenEncryptingAndSigningReadStream(
            Stream plainDataInputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingReadStream.Open(
                plainDataInputStream,
                encryptionSecretsSource.EncryptionSecrets,
                signingKeyRing,
                encoding,
                compression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingWriteStream OpenEncryptingAndSigningWriteStream(
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
            return PgpEncryptingWriteStream.Open(
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

        public PgpEncryptingReadStream OpenEncryptingAndSigningReadStream(
            Stream plainDataInputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingReadStream.Open(
                plainDataInputStream,
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

        public PgpEncryptingWriteStream OpenSplitEncryptingWriteStream(
            Stream messageOutputStream,
            Stream keyPacketsOutputStream,
            PgpCompression messageCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingWriteStream.OpenSplit(
                messageOutputStream,
                keyPacketsOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                messageCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingReadStream OpenSplitEncryptingReadStream(
            Stream plainDataInputStream,
            Stream keyPacketsOutputStream,
            PgpCompression messageCompression = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingReadStream.OpenSplit(
                plainDataInputStream,
                keyPacketsOutputStream,
                encryptionSecretsSource.EncryptionSecrets,
                messageCompression,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);
        }

        public PgpEncryptingWriteStream OpenSplitEncryptingWriteStream(
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
            return PgpEncryptingWriteStream.OpenSplit(
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

        public PgpEncryptingReadStream OpenSplitEncryptingReadStream(
            Stream plainDataInputStream,
            Stream keyPacketsOutputStream,
            Stream signatureOutputStream,
            PgpPrivateKeyRing signingKeyRing,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            long? aeadStreamingChunkLength = null,
            TimeProvider? timeProviderOverride = null)
        {
            return PgpEncryptingReadStream.OpenSplit(
                plainDataInputStream,
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
