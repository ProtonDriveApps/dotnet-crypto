using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpArmorDecoder
{
    public static unsafe int Decode(ReadOnlySpan<byte> message, ReadOnlySpan<byte> output)
    {
        fixed (byte* outputPointer = output)
        {
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var goWriter = new GoExternalWriter(&outputWriter);

            Decode(message, goWriter);

            return outputWriter.NumberOfBytesWritten;
        }
    }

    public static ArraySegment<byte> Decode(ReadOnlySpan<byte> message)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForDecodedMessage(message.Length);

        Decode(message, outputStream);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static void Decode(ReadOnlySpan<byte> message, Stream outputStream)
    {
        var streamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var goWriter = new GoExternalWriter(streamHandle);

            Decode(message, goWriter);
        }
        catch
        {
            streamHandle.Free();
            throw;
        }
    }

    public static int GetMaxLengthAfterDecoding(int originalLength)
    {
        return MemoryProvider.EstimateDecodedLength(originalLength);
    }

    private static void Decode(ReadOnlySpan<byte> message, in GoExternalWriter goWriter)
    {
        using var goError = GoDecode(MemoryMarshal.GetReference(message), (nuint)message.Length, goWriter);

        goError.ThrowIfFailure();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_unarmor_message")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoDecode(in byte message, nuint messageLength, GoExternalWriter outputWriter);
}
