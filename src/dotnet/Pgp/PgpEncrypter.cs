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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            output,
            default,
            default,
            Unsafe.NullRef<InteropWriter>(),
            profile,
            aeadStreamingChunkLength,
            null,
            timeProviderOverride);
    }

    public static int EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        ReadOnlySpan<byte> output,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            output,
            signingKeyRing,
            default,
            Unsafe.NullRef<InteropWriter>(),
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);
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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* signatureOutputPointer = signatureOutput)
        {
            var signatureSpanWriter = new SpanWriter(signatureOutputPointer, signatureOutput.Length);
            var signatureWriter = InteropWriter.FromSpanWriter(&signatureSpanWriter);

            var outputLength = Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                output,
                signingKeyRing,
                signatureEncryptionState,
                signatureWriter,
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride);

            signatureLength = signatureSpanWriter.NumberOfBytesWritten;

            return outputLength;
        }
    }

    public static ArraySegment<byte> Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        return EncryptAndSign(input, encryptionSecrets, default, outputEncoding, outputCompression, profile, aeadStreamingChunkLength, null, timeProviderOverride);
    }

    public static ArraySegment<byte> EncryptAndSign(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForMessage(input.Length, 1, signingKeyRing.Count, outputEncoding);

        EncryptAndSignToStream(
            input,
            encryptionSecrets,
            outputStream,
            signingKeyRing,
            outputEncoding,
            outputCompression,
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);

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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
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
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);

        signature = signatureOutputStream.TryGetBuffer(out var signatureBuffer) ? signatureBuffer : outputStream.ToArray();

        return outputStream.TryGetBuffer(out var outputBuffer) ? outputBuffer : outputStream.ToArray();
    }

    public static void EncryptToStream(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            outputStream,
            default,
            default,
            Unsafe.NullRef<InteropWriter>(),
            profile,
            aeadStreamingChunkLength,
            null,
            timeProviderOverride);
    }

    public static void EncryptAndSignToStream(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        Stream outputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        Encrypt(
            input,
            encryptionSecrets,
            outputEncoding,
            outputCompression,
            outputStream,
            signingKeyRing,
            default,
            Unsafe.NullRef<InteropWriter>(),
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);
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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        var signatureRecordingStream = new ExceptionRecordingStream(signatureOutputStream);
        var signatureOutputStreamHandle = GCHandle.Alloc(signatureRecordingStream);

        try
        {
            var signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                outputStream,
                signingKeyRing,
                signatureEncryptionState,
                signatureWriter,
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride,
                signatureRecordingStream);
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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        textEncoding ??= Encoding.UTF8;
        var maxTextByteLength = textEncoding.GetMaxByteCount(input.Length);

        var textBytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(maxTextByteLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[maxTextByteLength];

        using (heapMemoryOwner)
        {
            var textByteLength = textEncoding.GetBytes(input, textBytes);

            return Encrypt(textBytes[..textByteLength], encryptionSecrets, outputEncoding, outputCompression, profile, aeadStreamingChunkLength, timeProviderOverride);
        }
    }

    public static ArraySegment<byte> EncryptAndSignText(
        string input,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        PgpCompression outputCompression = default,
        Encoding? textEncoding = null,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = default,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
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
                outputEncoding,
                outputCompression,
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride);
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
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
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
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride);
        }
    }

    private static unsafe int Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding,
        PgpCompression outputCompression,
        ReadOnlySpan<byte> output,
        PgpPrivateKeyRing signingKeyRing,
        EncryptionState signatureEncryptionState,
        in InteropWriter signatureWriterPointer,
        PgpProfile profile,
        long? aeadStreamingChunkLength,
        PgpSigningContext? signingContext,
        TimeProvider? timeProviderOverride)
    {
        fixed (byte* outputPointer = output)
        {
            var outputSpanWriter = new SpanWriter(outputPointer, output.Length);
            var outputWriter = InteropWriter.FromSpanWriter(&outputSpanWriter);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                outputWriter,
                signingKeyRing,
                signatureEncryptionState,
                signatureWriterPointer,
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride);

            return outputSpanWriter.NumberOfBytesWritten;
        }
    }

    private static void Encrypt(
        ReadOnlySpan<byte> input,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding outputEncoding,
        PgpCompression outputCompression,
        Stream outputStream,
        PgpPrivateKeyRing signingKeyRing,
        EncryptionState signatureEncryptionState,
        in InteropWriter signatureWriter,
        PgpProfile profile,
        long? aeadStreamingChunkLength,
        PgpSigningContext? signingContext,
        TimeProvider? timeProviderOverride,
        ExceptionRecordingStream? signatureRecordingStream = null)
    {
        var outputRecordingStream = new ExceptionRecordingStream(outputStream);
        var outputStreamHandle = GCHandle.Alloc(outputRecordingStream);

        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(outputStreamHandle);

            Encrypt(
                input,
                encryptionSecrets,
                outputEncoding,
                outputCompression,
                outputWriter,
                signingKeyRing,
                signatureEncryptionState,
                signatureWriter,
                profile,
                aeadStreamingChunkLength,
                signingContext,
                timeProviderOverride,
                outputRecordingStream,
                signatureRecordingStream);
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
        in InteropWriter outputWriter,
        PgpPrivateKeyRing signingKeyRing,
        EncryptionState signatureEncryptionState,
        in InteropWriter signatureWriter,
        PgpProfile profile,
        long? aeadStreamingChunkLength,
        PgpSigningContext? signingContext,
        TimeProvider? timeProviderOverride,
        ExceptionRecordingStream? outputRecordingStream = null,
        ExceptionRecordingStream? signatureRecordingStream = null)
    {
        var (encryptionKeyRing, sessionKey, password) = encryptionSecrets;

        fixed (nint* encryptionKeysPointer = encryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* signingKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
                {
                    var parameters = new InteropEncryptionParameters(
                        profile,
                        encryptionKeysPointer,
                        (nuint)encryptionKeyRing.Count,
                        signingKeysPointer,
                        (nuint)signingKeyRing.Count,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        !Unsafe.IsNullRef(in signatureWriter),
                        signatureEncryptionState == EncryptionState.Encrypted,
                        outputCompression != PgpCompression.None,
                        aeadStreamingChunkLength,
                        signingContext,
                        timeProviderOverride);

                    using var error = ForeignFunctions.Encrypt(
                        parameters,
                        MemoryMarshal.GetReference(input),
                        (nuint)input.Length,
                        outputEncoding.ToInteropEncoding(),
                        signatureWriter,
                        outputWriter);

                    error.ThrowPgpOrStreamExceptionIfAny(outputRecordingStream, signatureRecordingStream);
                }
            }
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Encrypt(
            in InteropEncryptionParameters parameters,
            in byte message,
            nuint messageLength,
            InteropPgpEncoding encoding,
            in InteropWriter signatureWriter,
            InteropWriter outputWriter);
    }
}
