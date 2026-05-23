using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public static partial class PgpArmorEncoder
{
    public static unsafe int Encode(ReadOnlySpan<byte> message, PgpBlockType blockType, Span<byte> output)
    {
        fixed (byte* outputPointer = output)
        {
            var outputSpanWriter = new SpanWriter(outputPointer, output.Length);
            var outputWriter = InteropWriter.FromSpanWriter(&outputSpanWriter);

            Encode(message, blockType, outputWriter);

            return outputSpanWriter.NumberOfBytesWritten;
        }
    }

    public static ArraySegment<byte> Encode(ReadOnlySpan<byte> message, PgpBlockType blockType)
    {
        using var outputStream = MemoryProvider.GetMemoryStreamForDecodedMessage(message.Length);

        Encode(message, blockType, outputStream);

        return outputStream.TryGetBuffer(out var buffer) ? buffer : outputStream.ToArray();
    }

    public static void Encode(ReadOnlySpan<byte> message, PgpBlockType blockType, Stream outputStream)
    {
        var outputStreamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(outputStreamHandle);

            Encode(message, blockType, outputWriter);
        }
        catch
        {
            outputStreamHandle.Free();
            throw;
        }
    }

    public static int GetMaxLengthAfterEncoding(int originalLength)
    {
        return MemoryProvider.EstimateEncodedLength(originalLength, PgpEncoding.AsciiArmor);
    }

    private static void Encode(ReadOnlySpan<byte> message, PgpBlockType blockType, in InteropWriter outputWriter)
    {
        using var error = ForeignFunctions.Encode(MemoryMarshal.GetReference(message), (nuint)message.Length, blockType, outputWriter);

        error.ThrowPgpExceptionIfAny();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_armor_message")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Encode(in byte message, nuint messageLength, PgpBlockType blockType, InteropWriter outputWriter);
    }
}
