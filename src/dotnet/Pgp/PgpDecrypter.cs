using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpDecrypter
{
    public static unsafe int Decrypt(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        Span<byte> output,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* outputPointer = output)
        {
            var outputSpanWriter = new SpanWriter(outputPointer, output.Length);
            var outputWriter = new InteropPlaintextResult(&outputSpanWriter);

            Decrypt(input, inputEncoding, secrets, null, 0, default, default, [], ref outputWriter, timeProviderOverride);

            return outputSpanWriter.NumberOfBytesWritten;
        }
    }

    public static unsafe int DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        return Decrypt(input, inputEncoding, secrets, null, 0, default, default, verificationKeyRing, output, out verificationResult, timeProviderOverride);
    }

    public static unsafe int DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* signaturePointer = signature)
        {
            return Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signature.Length,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing,
                output,
                out verificationResult,
                timeProviderOverride);
        }
    }

    public static unsafe void Decrypt(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        Stream outputStream,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);

        try
        {
            var plaintextResult = new InteropPlaintextResult(outputStreamHandle);

            Decrypt(input, inputEncoding, secrets, null, 0, default, default, [], ref plaintextResult, timeProviderOverride);
        }
        finally
        {
            outputStreamHandle.Free();
        }
    }

    public static unsafe void DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        Stream outputStream,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        Decrypt(input, inputEncoding, secrets, null, 0, default, default, verificationKeyRing, outputStream, out verificationResult, timeProviderOverride);
    }

    public static unsafe void DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        Stream outputStream,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* signaturePointer = signature)
        {
            Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signature.Length,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing,
                outputStream,
                out verificationResult,
                timeProviderOverride);
        }
    }

    public static ArraySegment<byte> Decrypt(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForPlaintext(input.Length, inputEncoding);

        Decrypt(input, secrets, outputStream, inputEncoding, timeProviderOverride);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static ArraySegment<byte> DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        return DecryptAndVerify(
            input,
            secrets,
            default,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            timeProviderOverride: timeProviderOverride);
    }

    public static ArraySegment<byte> DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForPlaintext(input.Length, inputEncoding);

        DecryptAndVerify(
            input,
            secrets,
            signature,
            verificationKeyRing,
            outputStream,
            out verificationResult,
            inputEncoding,
            signatureEncoding,
            signatureEncryptionState,
            timeProviderOverride);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static string DecryptText(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
    {
        var decryptedBytes = Decrypt(input, secrets, inputEncoding, timeProviderOverride);

        textEncoding ??= Encoding.UTF8;

        return textEncoding.GetString(decryptedBytes);
    }

    public static string DecryptAndVerifyText(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
    {
        var decryptedBytes = DecryptAndVerify(input, secrets, verificationKeyRing, out verificationResult, inputEncoding, timeProviderOverride);

        textEncoding ??= Encoding.UTF8;

        return textEncoding.GetString(decryptedBytes);
    }

    public static string DecryptAndVerifyText(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = null,
        TimeProvider? timeProviderOverride = null)
    {
        var decryptedBytes = DecryptAndVerify(
            input,
            secrets,
            signature,
            verificationKeyRing,
            out verificationResult,
            inputEncoding,
            timeProviderOverride: timeProviderOverride);

        textEncoding ??= Encoding.UTF8;

        return textEncoding.GetString(decryptedBytes);
    }

    public static unsafe PgpSessionKey DecryptSessionKey(ReadOnlySpan<byte> keyPackets, in PgpPrivateKeyRing decryptionKeyRing)
    {
        fixed (nint* decryptionKeysPointer = decryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropDecryptionParameters(
                decryptionKeysPointer,
                (nuint)decryptionKeyRing.Count,
                null,
                0,
                null,
                null,
                0,
                null,
                0,
                default,
                default,
                null);

            using var error = ForeignFunctions.DecryptSessionKey(
                parameters,
                MemoryMarshal.GetReference(keyPackets),
                (nuint)keyPackets.Length,
                out var sessionKeyHandle);

            error.ThrowPgpExceptionIfAny();

            return new PgpSessionKey(sessionKeyHandle);
        }
    }

    private static unsafe int Decrypt(
        ReadOnlySpan<byte> input,
        PgpEncoding inputEncoding,
        in DecryptionSecrets secrets,
        byte* signaturePointer,
        int signatureLength,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        TimeProvider? timeProviderOverride)
    {
        fixed (byte* outputPointer = output)
        {
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var plaintextResult = new InteropPlaintextResult(&outputWriter);

            Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signatureLength,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing.DangerousGetForeignKeyHandles(),
                ref plaintextResult,
                timeProviderOverride);

            verificationResult = plaintextResult.HasVerificationResult
                ? new PgpVerificationResult(plaintextResult.VerificationResultHandle)
                : throw new PgpException("Missing verification result");

            return outputWriter.NumberOfBytesWritten;
        }
    }

    private static unsafe void Decrypt(
        ReadOnlySpan<byte> input,
        PgpEncoding inputEncoding,
        in DecryptionSecrets secrets,
        byte* signaturePointer,
        int signatureLength,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        PgpKeyRing verificationKeyRing,
        Stream outputStream,
        out PgpVerificationResult verificationResult,
        TimeProvider? timeProviderOverride)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);

        try
        {
            var plaintextResult = new InteropPlaintextResult(outputStreamHandle);

            Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signatureLength,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing.DangerousGetForeignKeyHandles(),
                ref plaintextResult,
                timeProviderOverride);

            verificationResult = plaintextResult.HasVerificationResult
                ? new PgpVerificationResult(plaintextResult.VerificationResultHandle)
                : throw new PgpException("Missing verification result");
        }
        finally
        {
            outputStreamHandle.Free();
        }
    }

    private static unsafe void Decrypt(
        ReadOnlySpan<byte> input,
        PgpEncoding inputEncoding,
        in DecryptionSecrets secrets,
        byte* signaturePointer,
        int signatureLength,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        ReadOnlySpan<nint> verificationKeyHandles,
        ref InteropPlaintextResult plaintextResult,
        TimeProvider? timeProviderOverride)
    {
        var (decryptionKeyRing, sessionKey, password) = secrets;

        fixed (nint* decryptionKeysPointer = decryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* verificationKeysPointer = verificationKeyHandles)
                {
                    var parameters = new InteropDecryptionParameters(
                        decryptionKeysPointer,
                        (nuint)decryptionKeyRing.Count,
                        verificationKeysPointer,
                        (nuint)verificationKeyHandles.Length,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        signaturePointer,
                        (nuint)signatureLength,
                        signatureEncoding,
                        signatureEncryptionState,
                        timeProviderOverride);

                    using var error = ForeignFunctions.Decrypt(
                        parameters,
                        MemoryMarshal.GetReference(input),
                        (nuint)input.Length,
                        inputEncoding.ToInteropEncoding(),
                        ref plaintextResult);

                    error.ThrowPgpExceptionIfAny();
                }
            }
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_decrypt")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Decrypt(
            in InteropDecryptionParameters parameters,
            in byte body,
            nuint bodyLength,
            InteropPgpEncoding encoding,
            ref InteropPlaintextResult plaintextResult);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_decrypt_session_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError DecryptSessionKey(
            in InteropDecryptionParameters parameters,
            in byte keyPackets,
            nuint keyPacketsLength,
            out nint sessionKeyHandle);
    }
}
