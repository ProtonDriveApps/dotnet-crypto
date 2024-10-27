using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpDecrypter
{
    public static unsafe int Decrypt(ReadOnlySpan<byte> input, in DecryptionSecrets secrets, Span<byte> output, PgpEncoding inputEncoding = default)
    {
        fixed (byte* outputPointer = output)
        {
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var goResult = new GoPlaintextResult(&outputWriter);

            Decrypt(input, inputEncoding, secrets, default, default, default, default, [], ref goResult);

            return outputWriter.NumberOfBytesWritten;
        }
    }

    public static unsafe int DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        Span<byte> output,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default)
    {
        return Decrypt(input, inputEncoding, secrets, default, default, default, default, verificationKeyRing, output, out verificationResult);
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
        EncryptionState signatureEncryptionState = default)
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
                out verificationResult);
        }
    }

    public static unsafe void Decrypt(ReadOnlySpan<byte> input, in DecryptionSecrets secrets, Stream outputStream, PgpEncoding inputEncoding = default)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);

        try
        {
            var goResult = new GoPlaintextResult(outputStreamHandle);

            Decrypt(input, inputEncoding, secrets, default, default, default, default, [], ref goResult);
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
        PgpEncoding inputEncoding = default)
    {
        Decrypt(input, inputEncoding, secrets, default, default, default, default, verificationKeyRing, outputStream, out verificationResult);
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
        EncryptionState signatureEncryptionState = default)
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
                out verificationResult);
        }
    }

    public static ArraySegment<byte> Decrypt(ReadOnlySpan<byte> input, in DecryptionSecrets secrets, PgpEncoding inputEncoding = default)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForPlaintext(input.Length, inputEncoding);

        Decrypt(input, secrets, outputStream, inputEncoding);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static ArraySegment<byte> DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default)
    {
        return DecryptAndVerify(input, secrets, default, verificationKeyRing, out verificationResult, inputEncoding);
    }

    public static ArraySegment<byte> DecryptAndVerify(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default)
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
            signatureEncryptionState);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static string DecryptText(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = default)
    {
        var decryptedBytes = Decrypt(input, secrets, inputEncoding);

        textEncoding ??= Encoding.UTF8;

        return textEncoding.GetString(decryptedBytes);
    }

    public static string DecryptAndVerifyText(
        ReadOnlySpan<byte> input,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        out PgpVerificationResult verificationResult,
        PgpEncoding inputEncoding = default,
        Encoding? textEncoding = default)
    {
        var decryptedBytes = DecryptAndVerify(input, secrets, verificationKeyRing, out verificationResult, inputEncoding);

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
        Encoding? textEncoding = default)
    {
        var decryptedBytes = DecryptAndVerify(input, secrets, signature, verificationKeyRing, out verificationResult, inputEncoding);

        textEncoding ??= Encoding.UTF8;

        return textEncoding.GetString(decryptedBytes);
    }

    public static unsafe PgpSessionKey DecryptSessionKey(ReadOnlySpan<byte> keyPackets, in PgpPrivateKeyRing decryptionKeyRing)
    {
        fixed (nint* goDecryptionKeysPointer = decryptionKeyRing.GoKeyHandles)
        {
            var parameters = new GoDecryptionParameters(
                goDecryptionKeysPointer,
                (nuint)decryptionKeyRing.Count,
                default,
                default,
                default,
                default,
                default,
                default,
                default,
                default,
                default);

            using var goError = GoDecryptSessionKey(
                parameters,
                MemoryMarshal.GetReference(keyPackets),
                (nuint)keyPackets.Length,
                out var unsafeGoSessionKeyHandle);

            goError.ThrowIfFailure();

            return new PgpSessionKey(new GoSessionKey(unsafeGoSessionKeyHandle));
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
        out PgpVerificationResult verificationResult)
    {
        fixed (byte* outputPointer = output)
        {
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var goResult = new GoPlaintextResult(&outputWriter);

            Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signatureLength,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing.GoKeyHandles,
                ref goResult);

            verificationResult = goResult.HasVerificationResult
                ? new PgpVerificationResult(new GoVerificationResult(goResult.VerificationResultHandle))
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
        out PgpVerificationResult verificationResult)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);

        try
        {
            var goResult = new GoPlaintextResult(outputStreamHandle);

            Decrypt(
                input,
                inputEncoding,
                secrets,
                signaturePointer,
                signatureLength,
                signatureEncoding,
                signatureEncryptionState,
                verificationKeyRing.GoKeyHandles,
                ref goResult);

            verificationResult = goResult.HasVerificationResult
                ? new PgpVerificationResult(new GoVerificationResult(goResult.VerificationResultHandle))
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
        ReadOnlySpan<nint> goVerificationKeyHandles,
        ref GoPlaintextResult goResult)
    {
        var (goDecryptionKeyHandles, sessionKey, password) = secrets;

        fixed (nint* goDecryptionKeysPointer = goDecryptionKeyHandles)
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* goVerificationKeysPointer = goVerificationKeyHandles)
                {
                    var parameters = new GoDecryptionParameters(
                        goDecryptionKeysPointer,
                        (nuint)goDecryptionKeyHandles.Length,
                        goVerificationKeysPointer,
                        (nuint)goVerificationKeyHandles.Length,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        signaturePointer,
                        (nuint)signatureLength,
                        signatureEncoding,
                        signatureEncryptionState);

                    using var goError = GoDecrypt(
                        parameters,
                        MemoryMarshal.GetReference(input),
                        (nuint)input.Length,
                        inputEncoding.ToGoEncoding(),
                        ref goResult);

                    goError.ThrowIfFailure();
                }
            }
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_decrypt")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoDecrypt(
        in GoDecryptionParameters parameters,
        in byte body,
        nuint bodyLength,
        GoPgpEncoding encoding,
        ref GoPlaintextResult result);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_decrypt_session_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoDecryptSessionKey(
        in GoDecryptionParameters parameters,
        in byte keyPackets,
        nuint keyPacketsLength,
        out nint sessionKeyHandle);
}
