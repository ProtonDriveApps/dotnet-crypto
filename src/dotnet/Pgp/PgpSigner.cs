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
        TimeProvider? timeProviderOverride = null)
    {
        using var outputStream = outputType == SigningOutputType.FullMessage
            ? MemoryProvider.GetMemoryStreamForMessage(input.Length, 0, signingKeyRing.Count, outputEncoding)
            : MemoryProvider.GetMemoryStreamForSignature(signingKeyRing.Count, outputEncoding);

        Sign(input, signingKeyRing, outputStream, outputEncoding, outputType, timeProviderOverride);

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
        TimeProvider? timeProviderOverride = null)
    {
        fixed (byte* signatureOutputPointer = signatureOutput)
        {
            var outputWriter = new SpanWriter(signatureOutputPointer, signatureOutput.Length);
            var goWriter = new GoExternalWriter(&outputWriter);

            Sign(input, signingKeyRing, goWriter, outputEncoding, outputType, timeProviderOverride);

            return outputWriter.NumberOfBytesWritten;
        }
    }

    public static void Sign(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        TimeProvider? timeProviderOverride = null)
    {
        using var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, outputType, timeProviderOverride);

        inputStream.CopyTo(signingStream);
    }

    public static async Task SignAsync(
        Stream inputStream,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        CancellationToken cancellationToken,
        PgpEncoding outputEncoding = default,
        SigningOutputType outputType = default,
        TimeProvider? timeProviderOverride = null)
    {
        var signingStream = PgpSigningStream.Open(outputStream, signingKeyRing, outputEncoding, outputType, timeProviderOverride);

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
        TimeProvider? timeProviderOverride = null)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var goWriter = new GoExternalWriter(outputStreamHandle);

            Sign(input, signingKeyRing, goWriter, outputEncoding, outputType, timeProviderOverride);
        }
        finally
        {
            outputStreamHandle.Free();
        }
    }

    public static unsafe void SignCleartext(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        Stream outputStream,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goSigningKeysPointer = signingKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new GoSigningParameters(goSigningKeysPointer, (nuint)signingKeyRing.Count, timeProviderOverride);

            var outputStreamHandle = GCHandle.Alloc(outputStream);
            try
            {
                var goWriter = new GoExternalWriter(outputStreamHandle);

                using var goError = GoSignCleartext(parameters, MemoryMarshal.GetReference(input), (nuint)input.Length, goWriter);
                goError.ThrowIfFailure();
            }
            finally
            {
                outputStreamHandle.Free();
            }
        }
    }

    private static unsafe void Sign(
        ReadOnlySpan<byte> input,
        PgpPrivateKeyRing signingKeyRing,
        in GoExternalWriter goWriter,
        PgpEncoding outputEncoding,
        SigningOutputType outputType,
        TimeProvider? timeProviderOverride)
    {
        fixed (nint* goSigningKeysPointer = signingKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new GoSigningParameters(goSigningKeysPointer, (nuint)signingKeyRing.Count, timeProviderOverride);

            var detached = outputType == SigningOutputType.SignatureOnly;

            using var goError = GoSign(parameters, MemoryMarshal.GetReference(input), (nuint)input.Length, outputEncoding.ToGoEncoding(), detached, goWriter);

            goError.ThrowIfFailure();
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_sign")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoSign(
        in GoSigningParameters parameters,
        in byte data,
        nuint dataLength,
        GoPgpEncoding encoding,
        [MarshalAs(UnmanagedType.U1)] bool detached,
        GoExternalWriter outputWriter);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_sign_cleartext")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoSignCleartext(in GoSigningParameters parameters, in byte data, nuint dataLength, GoExternalWriter outputWriter);
}
