using System.Runtime.CompilerServices;
using CommunityToolkit.HighPerformance;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpSigner
{
    public static ArraySegment<byte> Sign(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForSignature(signingKeyRing.Count, outputEncoding);

        using (var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, timeProviderOverride: timeProviderOverride))
        {
            inputStream.CopyTo(signingStream);
        }

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static async Task<ArraySegment<byte>> SignAsync(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        var outputStream = MemoryProvider.GetMemoryStreamForSignature(signingKeyRing.Count, outputEncoding);

        await using (outputStream.ConfigureAwait(false))
        {
            var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, timeProviderOverride: timeProviderOverride);

            await using (signingStream.ConfigureAwait(false))
            {
                await inputStream.CopyToAsync(signingStream, cancellationToken).ConfigureAwait(false);
            }
        }

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static ArraySegment<byte> Sign(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = outputType == SigningOutputType.FullMessage
            ? MemoryProvider.GetMemoryStreamForMessage(input.Length, 0, signingKeyRing.Count, outputEncoding)
            : MemoryProvider.GetMemoryStreamForSignature(signingKeyRing.Count, outputEncoding);

        Sign(input, signingKeyRing, outputStream, outputEncoding, outputType, profile, timeProviderOverride);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static unsafe int Sign(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Span<byte> signatureOutput,
        PgpEncoding outputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* outputPointer = signatureOutput)
        {
            var outputStream = new UnmanagedMemoryStream(outputPointer, signatureOutput.Length);

            using var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, timeProviderOverride: timeProviderOverride);

            inputStream.CopyTo(signingStream);

            return (int)outputStream.Length;
        }
    }

    public static async Task<int> SignAsync(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Memory<byte> output,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        var outputStream = output.AsStream();

        var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, timeProviderOverride: timeProviderOverride);

        await using (signingStream)
        {
            await inputStream.CopyToAsync(signingStream, cancellationToken).ConfigureAwait(false);

            return (int)outputStream.Length;
        }
    }

    public static unsafe int Sign(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        Span<byte> signatureOutput,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* signatureOutputPointer = signatureOutput)
        {
            var outputSpanWriter = new SpanWriter(signatureOutputPointer, signatureOutput.Length);
            var outputWriter = InteropWriter.FromSpanWriter(&outputSpanWriter);

            Sign(input, signingKeyRing, outputWriter, outputEncoding, outputType, profile, timeProviderOverride);

            return outputSpanWriter.NumberOfBytesWritten;
        }
    }

    public static void Sign(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, outputType, profile, timeProviderOverride);

        inputStream.CopyTo(signingStream);
    }

    public static async Task SignAsync(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, outputType, profile, timeProviderOverride);

        await using (signingStream.ConfigureAwait(false))
        {
            await inputStream.CopyToAsync(signingStream, cancellationToken).ConfigureAwait(false);
        }
    }

    public static void Sign(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(outputStreamHandle);

            Sign(input, signingKeyRing, outputWriter, outputEncoding, outputType, profile, timeProviderOverride);
        }
        finally
        {
            outputStreamHandle.Free();
        }
    }

    private static unsafe void Sign(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        in InteropWriter outputWriter,
        PgpEncoding outputEncoding,
        SigningOutputType outputType,
        PgpProfile profile,
        TimeProvider? timeProviderOverride)
    {
        fixed (nint* signingKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropSigningParameters(signingKeysPointer, (nuint)signingKeyRing.Count, profile, timeProviderOverride);

            var detached = outputType == SigningOutputType.SignatureOnly;

            using var error = ForeignFunctions.Sign(
                parameters,
                MemoryMarshal.GetReference(input),
                (nuint)input.Length,
                outputEncoding.ToInteropEncoding(),
                detached,
                outputWriter);

            error.ThrowPgpExceptionIfAny();
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_sign")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Sign(
            in InteropSigningParameters parameters,
            in byte data,
            nuint dataLength,
            InteropPgpEncoding encoding,
            [MarshalAs(UnmanagedType.U1)] bool detached,
            InteropWriter outputWriter);
    }
}
