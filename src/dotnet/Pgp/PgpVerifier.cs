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
        fixed (nint* verificationKeysPointer = verificationKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropVerificationParameters(verificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            var messageStreamHandle = GCHandle.Alloc(messageStream);

            try
            {
                var inputReader = new InteropReader(messageStreamHandle);

                using var error = ForeignFunctions.VerifyInlineStream(parameters, inputReader, encoding.ToInteropEncoding(), out var outputReaderHandle);
                error.ThrowPgpExceptionIfAny();

                using var outputReader = new ForeignReader(outputReaderHandle);

                // TODO: expose the output reader as a stream and let the caller read from it instead of reading everything here and discarding it
                Span<byte> buffer = stackalloc byte[4096];
                while (outputReader.Read(buffer) > 0)
                {
                }

                return outputReader.GetVerificationResult();
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
        fixed (nint* verificationKeysPointer = verificationKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropVerificationParameters(verificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            var messageStreamHandle = GCHandle.Alloc(inputStream);

            try
            {
                var inputReader = new InteropReader(messageStreamHandle);

                using var error = ForeignFunctions.VerifyDetachedStream(
                    parameters,
                    inputReader,
                    MemoryMarshal.GetReference(signature),
                    (nuint)signature.Length,
                    encoding.ToInteropEncoding(),
                    out var verificationResultHandle);

                error.ThrowPgpExceptionIfAny();

                return new PgpVerificationResult(verificationResultHandle);
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
        fixed (nint* keysPointer = keyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropVerificationParameters(keysPointer, (nuint)keyRing.Count, timeProviderOverride);

            var streamHandle = GCHandle.Alloc(Stream.Null);

            try
            {
                var plaintextResult = new InteropPlaintextResult(streamHandle);

                using var error = ForeignFunctions.VerifyInline(
                    parameters,
                    MemoryMarshal.GetReference(message),
                    (nuint)message.Length,
                    encoding.ToInteropEncoding(),
                    ref plaintextResult);

                error.ThrowPgpExceptionIfAny();

                return new PgpVerificationResult(plaintextResult.VerificationResultHandle);
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
        fixed (nint* verificationKeysPointer = verificationKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropVerificationParameters(verificationKeysPointer, (nuint)verificationKeyRing.Count, timeProviderOverride);

            using var error = ForeignFunctions.VerifyDetached(
                parameters,
                MemoryMarshal.GetReference(input),
                (nuint)input.Length,
                MemoryMarshal.GetReference(signature),
                (nuint)signature.Length,
                encoding.ToInteropEncoding(),
                out var verificationResultHandle);

            if (verificationResultHandle == 0)
            {
                error.ThrowPgpExceptionIfAny();
            }

            return new PgpVerificationResult(verificationResultHandle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe readonly struct InteropVerificationParameters
    {
        public readonly nuint KeysLength;
        public readonly bool HasVerificationTime;
        public readonly bool HasVerificationContext;
        public readonly bool IsUtf8;
        public readonly nint* Keys;
        public readonly nint VerificationContext;
        public readonly ulong VerificationTime;

        public InteropVerificationParameters(nint* verificationKeys, nuint verificationKeysLength, TimeProvider? timeProviderOverride)
        {
            Keys = verificationKeys;
            KeysLength = verificationKeysLength;

            var timeProvider = timeProviderOverride ?? PgpConfiguration.DefaultTimeProviderOverride;

            if (timeProvider is not null)
            {
                HasVerificationTime = true;

                VerificationTime = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            }
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verify_detached")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError VerifyDetached(
            in InteropVerificationParameters parameters,
            in byte data,
            nuint dataLength,
            in byte signature,
            nuint signatureLength,
            InteropPgpEncoding encoding,
            out nint verificationResultHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verify_detached_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError VerifyDetachedStream(
            in InteropVerificationParameters parameters,
            InteropReader inputReader,
            in byte signature,
            nuint signatureLength,
            InteropPgpEncoding encoding,
            out nint verificationResultHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verify_inline")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError VerifyInline(
            in InteropVerificationParameters parameters,
            in byte data,
            nuint dataLength,
            InteropPgpEncoding encoding,
            ref InteropPlaintextResult plaintextResult);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verify_inline_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError VerifyInlineStream(
            in InteropVerificationParameters parameters,
            InteropReader inputReader,
            InteropPgpEncoding encoding,
            out nint readerHandle);
    }
}
