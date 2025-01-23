using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpVerifier
{
    public static unsafe PgpVerificationResult Verify(
        Stream messageStream,
        PgpKeyRing verificationKeyRing,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goVerificationKeysPointer = verificationKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new VerificationParameters(goVerificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            var messageStreamHandle = GCHandle.Alloc(messageStream);

            try
            {
                var goReader = new GoExternalReader(messageStreamHandle);

                using var goError = GoVerifyInlineStream(parameters, goReader, encoding.ToGoEncoding(), out var unsafeGoVerificationResultHandle);
                goError.ThrowIfFailure();

                return new PgpVerificationResult(new GoVerificationResult(unsafeGoVerificationResultHandle));
            }
            finally
            {
                messageStreamHandle.Free();
            }
        }
    }

    public static unsafe PgpVerificationResult Verify(
        Stream inputStream,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goVerificationKeysPointer = verificationKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new VerificationParameters(goVerificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            var messageStreamHandle = GCHandle.Alloc(inputStream);

            try
            {
                var goReader = new GoExternalReader(messageStreamHandle);

                using var goError = GoVerifyDetachedStream(
                    parameters,
                    goReader,
                    MemoryMarshal.GetReference(signature),
                    (nuint)signature.Length,
                    encoding.ToGoEncoding(),
                    out var unsafeGoVerificationResultHandle);

                goError.ThrowIfFailure();

                return new PgpVerificationResult(new GoVerificationResult(unsafeGoVerificationResultHandle));
            }
            finally
            {
                messageStreamHandle.Free();
            }
        }
    }

    public static unsafe PgpVerificationResult Verify(
        ReadOnlySpan<byte> message,
        PgpKeyRing keyRing,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goKeysPointer = keyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new VerificationParameters(goKeysPointer, (nuint)keyRing.Count, timeProviderOverride);

            var streamHandle = GCHandle.Alloc(Stream.Null);

            try
            {
                var goPlaintextResult = new GoPlaintextResult(streamHandle);

                using var goError = GoVerifyInline(
                    parameters,
                    MemoryMarshal.GetReference(message),
                    (nuint)message.Length,
                    encoding.ToGoEncoding(),
                    ref goPlaintextResult);

                goError.ThrowIfFailure();

                return new PgpVerificationResult(new GoVerificationResult(goPlaintextResult.VerificationResultHandle));
            }
            finally
            {
                streamHandle.Free();
            }
        }
    }

    public static unsafe PgpVerificationResult Verify(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> signature,
        PgpKeyRing verificationKeyRing,
        PgpEncoding encoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goVerificationKeysPointer = verificationKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new VerificationParameters(goVerificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            using var goError = GoVerifyDetached(
                parameters,
                MemoryMarshal.GetReference(input),
                (nuint)input.Length,
                MemoryMarshal.GetReference(signature),
                (nuint)signature.Length,
                encoding.ToGoEncoding(),
                out var unsafeGoVerificationResultHandle);

            if (unsafeGoVerificationResultHandle == 0)
            {
                goError.ThrowIfFailure();
            }

            return new PgpVerificationResult(new GoVerificationResult(unsafeGoVerificationResultHandle));
        }
    }

    public static unsafe PgpVerificationResult VerifyCleartext(
        ReadOnlySpan<byte> message,
        PgpKeyRing verificationKeyRing,
        Stream cleartextOutputStream,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goVerificationKeysPointer = verificationKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new VerificationParameters(goVerificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            var cleartextOutputStreamHandle = GCHandle.Alloc(cleartextOutputStream);

            try
            {
                var goResult = new GoPlaintextResult(cleartextOutputStreamHandle);

                using var goError = GoVerifyCleartext(parameters, MemoryMarshal.GetReference(message), (nuint)message.Length, ref goResult);
                goError.ThrowIfFailure();

                return goResult.HasVerificationResult
                    ? new PgpVerificationResult(new GoVerificationResult(goResult.VerificationResultHandle))
                    : throw new PgpException("Missing verification result");
            }
            finally
            {
                cleartextOutputStreamHandle.Free();
            }
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verify_detached")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyDetached(
        in VerificationParameters parameters,
        in byte data,
        nuint dataLength,
        in byte signature,
        nuint signatureLength,
        GoPgpEncoding encoding,
        out nint verificationResultHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verify_detached_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyDetachedStream(
        in VerificationParameters parameters,
        GoExternalReader inputReader,
        in byte signature,
        nuint signatureLength,
        GoPgpEncoding encoding,
        out nint verificationResultHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verify_inline")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyInline(
        in VerificationParameters parameters,
        in byte data,
        nuint dataLength,
        GoPgpEncoding encoding,
        ref GoPlaintextResult plaintextResult);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verify_inline_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyInlineStream(
        in VerificationParameters parameters,
        GoExternalReader inputReader,
        GoPgpEncoding encoding,
        out nint readerHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verify_cleartext")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyCleartext(
        in VerificationParameters parameters,
        in byte message,
        nuint messageLength,
        ref GoPlaintextResult plaintextResult);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe readonly struct VerificationParameters
    {
        public readonly nuint KeysLength;
        public readonly bool HasVerificationTime;
        public readonly bool HasVerificationContext;
        public readonly bool IsUtf8;
        public readonly nint* Keys;
        public readonly nint VerificationContext;
        public readonly long VerificationTime;

        public VerificationParameters(nint* verificationKeys, nuint verificationKeysLength, TimeProvider? timeProviderOverride)
        {
            Keys = verificationKeys;
            KeysLength = verificationKeysLength;

            var timeProvider = timeProviderOverride ?? PgpEnvironment.DefaultTimeProviderOverride;

            if (timeProvider is not null)
            {
                HasVerificationTime = true;
                VerificationTime = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            }
        }
    }
}
