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
            var outputWriter = new SpanWriter(outputPointer, output.Length);
            var goWriter = new GoExternalWriter(&outputWriter);

            Encode(message, blockType, goWriter);

            return outputWriter.NumberOfBytesWritten;
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
        var streamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var goWriter = new GoExternalWriter(streamHandle);

            Encode(message, blockType, goWriter);
        }
        catch
        {
            streamHandle.Free();
            throw;
        }
    }

    public static int GetMaxLengthAfterEncoding(int originalLength)
    {
        return MemoryProvider.EstimateEncodedLength(originalLength, PgpEncoding.AsciiArmor);
    }

    private static void Encode(ReadOnlySpan<byte> message, PgpBlockType blockType, in GoExternalWriter goWriter)
    {
        using var goError = GoEncode(MemoryMarshal.GetReference(message), (nuint)message.Length, blockType, goWriter);

        goError.ThrowIfFailure();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_armor_message")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoEncode(in byte message, nuint messageLength, PgpBlockType blockType, GoExternalWriter outputWriter);
}
