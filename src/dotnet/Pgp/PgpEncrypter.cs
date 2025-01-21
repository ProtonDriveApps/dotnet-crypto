using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpEncrypter
{
    public static int Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        ReadOnlySpan<byte> output,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        return Encrypt(input, encryptionSecrets, outputEncoding, outputCompression, output, [], default, Unsafe.NullRef<GoExternalWriter>(), timestamp);
    }

    public static int EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        ReadOnlySpan<byte> output,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        return Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            output,
            signingKeyRing,
            default,
            Unsafe.NullRef<GoExternalWriter>(),
            timestamp);
    }

    public static unsafe int EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        ReadOnlySpan<byte> output,
        PgpPrivateKeyRing signingKeyRing,
        ReadOnlySpan<byte> signatureOutput,
        out int signatureLength,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        DateTime? timestamp = null)
    {
        fixed (byte* signatureOutputPointer = signatureOutput)
        {
            var signatureOutputWriter = new SpanWriter(signatureOutputPointer, signatureOutput.Length);
            var goSignatureWriter = new GoExternalWriter(&signatureOutputWriter);

            var outputLength = Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                output,
                signingKeyRing,
                signatureEncryptionState,
                goSignatureWriter,
                timestamp);

            signatureLength = signatureOutputWriter.NumberOfBytesWritten;

            return outputLength;
        }
    }

    public static ArraySegment<byte> Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        return EncryptAndSign(input, encryptionSecrets, default, outputEncoding, outputCompression, timestamp);
    }

    public static ArraySegment<byte> EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForMessage(input.Length, 1, signingKeyRing.Count, outputEncoding);

        EncryptAndSignToStream(input, encryptionSecrets, outputStream, signingKeyRing, outputEncoding, outputCompression, timestamp);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static ArraySegment<byte> EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        out ArraySegment<byte> signature,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        DateTime? timestamp = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForMessage(input.Length, 1, 0, outputEncoding);
        using var signatureOutputStream = MemoryProvider.GetMemoryStreamForSignature(signingKeyRing.Count, outputEncoding);

        EncryptAndSignToStreams(
            input,
            encryptionSecrets,
            outputStream,
            signingKeyRing,
            signatureOutputStream,
            outputEncoding,
            outputCompression,
            signatureEncryptionState,
            timestamp);

        signature = signatureOutputStream.TryGetBuffer(out var signatureBuffer) ? signatureBuffer : outputStream.ToArray();

        return outputStream.TryGetBuffer(out var outputBuffer) ? outputBuffer : outputStream.ToArray();
    }

    public static void EncryptToStream(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        Encrypt(input, encryptionSecrets, outputEncoding, outputCompression, outputStream, [], default, Unsafe.NullRef<GoExternalWriter>(), timestamp);
    }

    public static void EncryptAndSignToStream(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        Stream outputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        DateTime? timestamp = null)
    {
        Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            outputStream,
            signingKeyRing,
            default,
            Unsafe.NullRef<GoExternalWriter>(),
            timestamp);
    }

    public static void EncryptAndSignToStreams(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        Stream outputStream,
        PgpPrivateKeyRing signingKeyRing,
        Stream signatureOutputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        DateTime? timestamp = null)
    {
        var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);

        try
        {
            var goSignatureWriter = new GoExternalWriter(signatureOutputStreamHandle);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                outputStream,
                signingKeyRing,
                signatureEncryptionState,
                goSignatureWriter,
                timestamp);
        }
        finally
        {
            signatureOutputStreamHandle.Free();
        }
    }

    public static ArraySegment<byte> EncryptText(
        string input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        Encoding? textEncoding = null,
        DateTime? timestamp = null)
    {
        textEncoding ??= Encoding.UTF8;
        var maxTextByteLength = textEncoding.GetMaxByteCount(input.Length);

        var textBytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(maxTextByteLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[maxTextByteLength];

        using (heapMemoryOwner)
        {
            var textByteLength = textEncoding.GetBytes(input, textBytes);

            return Encrypt(textBytes[..textByteLength], encryptionSecrets, outputEncoding, outputCompression, timestamp);
        }
    }

    public static ArraySegment<byte> EncryptAndSignText(
        string input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        Encoding? textEncoding = null,
        DateTime? timestamp = null)
    {
        textEncoding ??= Encoding.UTF8;
        var maxTextByteLength = textEncoding.GetMaxByteCount(input.Length);

        var textBytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(maxTextByteLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[maxTextByteLength];

        using (heapMemoryOwner)
        {
            var textByteLength = textEncoding.GetBytes(input, textBytes);

            return EncryptAndSign(textBytes[..textByteLength], encryptionSecrets, signingKeyRing, outputEncoding, outputCompression, timestamp);
        }
    }

    public static ArraySegment<byte> EncryptAndSignText(
        string input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        out ArraySegment<byte> signature,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        EncryptionState signatureEncryptionState = default,
        Encoding? textEncoding = null,
        DateTime? timestamp = null)
    {
        textEncoding ??= Encoding.UTF8;
        var maxTextByteLength = textEncoding.GetMaxByteCount(input.Length);

        var textBytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(maxTextByteLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[maxTextByteLength];

        using (heapMemoryOwner)
        {
            var textByteLength = textEncoding.GetBytes(input, textBytes);

            return EncryptAndSign(
                textBytes[..textByteLength],
                encryptionSecrets,
                signingKeyRing,
                out signature,
                outputEncoding,
                outputCompression,
                signatureEncryptionState,
                timestamp);
        }
    }

    private static unsafe int Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding,
        PgpCompression outputCompression,
        ReadOnlySpan<byte> output,
        ReadOnlySpan<nint> goSigningKeyHandles,
        EncryptionState signatureEncryptionState,
        in GoExternalWriter goSignatureWriterPointer,
        DateTime? timestamp)
    {
        fixed (byte* outputPointer = output)
        {
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var goOutputWriter = new GoExternalWriter(&outputWriter);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                goOutputWriter,
                goSigningKeyHandles,
                signatureEncryptionState,
                goSignatureWriterPointer,
                timestamp);

            return outputWriter.NumberOfBytesWritten;
        }
    }

    private static void Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding,
        PgpCompression outputCompression,
        Stream outputStream,
        ReadOnlySpan<nint> goSigningKeyHandles,
        EncryptionState signatureEncryptionState,
        in GoExternalWriter goSignatureWriter,
        DateTime? timestamp)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);

        try
        {
            var goOutputWriter = new GoExternalWriter(outputStreamHandle);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                goOutputWriter,
                goSigningKeyHandles,
                signatureEncryptionState,
                goSignatureWriter,
                timestamp);
        }
        finally
        {
            outputStreamHandle.Free();
        }
    }

    private static unsafe void Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding,
        PgpCompression outputCompression,
        in GoExternalWriter goOutputWriter,
        ReadOnlySpan<nint> goSigningKeyHandles,
        EncryptionState signatureEncryptionState,
        in GoExternalWriter goSignatureWriter,
        DateTime? timestamp)
    {
        var (goEncryptionKeyHandles, sessionKey, password) = encryptionSecrets;

        fixed (nint* goEncryptionKeysPointer = goEncryptionKeyHandles)
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* goSigningKeysPointer = goSigningKeyHandles)
                {
                    var parameters = new GoEncryptionParameters(
                        goEncryptionKeysPointer,
                        (nuint)goEncryptionKeyHandles.Length,
                        goSigningKeysPointer,
                        (nuint)goSigningKeyHandles.Length,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        !Unsafe.IsNullRef(in goSignatureWriter),
                        signatureEncryptionState == EncryptionState.Encrypted,
                        outputCompression != PgpCompression.None,
                        timestamp);

                    var goEncoding = outputEncoding.ToGoEncoding();

                    using var goError = Encrypt(
                        parameters,
                        MemoryMarshal.GetReference(input),
                        (nuint)input.Length,
                        goEncoding,
                        goSignatureWriter,
                        goOutputWriter);

                    goError.ThrowIfFailure();
                }
            }
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError Encrypt(
        in GoEncryptionParameters parameters,
        in byte message,
        nuint messageLength,
        GoPgpEncoding encoding,
        in GoExternalWriter signatureWriter,
        GoExternalWriter outputWriter);
}
