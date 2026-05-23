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
            var outputSpanWriter = new SpanWriter(outputPointer, output.Length);
            var outputWriter = InteropWriter.FromSpanWriter(&outputSpanWriter);

            Decode(message, outputWriter);

            return outputSpanWriter.NumberOfBytesWritten;
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
        var outputStreamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(outputStreamHandle);

            Decode(message, outputWriter);
        }
        catch
        {
            outputStreamHandle.Free();
            throw;
        }
    }

    public static int GetMaxLengthAfterDecoding(int originalLength)
    {
        return MemoryProvider.EstimateDecodedLength(originalLength);
    }

    private static void Decode(ReadOnlySpan<byte> message, in InteropWriter outputWriter)
    {
        using var error = ForeignFunctions.Decode(MemoryMarshal.GetReference(message), (nuint)message.Length, outputWriter);

        error.ThrowPgpExceptionIfAny();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_unarmor_message")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Decode(in byte message, nuint messageLength, InteropWriter outputWriter);
    }
}
