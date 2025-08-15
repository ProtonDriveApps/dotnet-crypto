namespace Proton.Cryptography.Pgp.Interop;

internal unsafe struct SpanWriter(byte* destinationPointer, int destinationLength)
{
    public int NumberOfBytesWritten;

    public int Write(ReadOnlySpan<byte> bytes, bool allowPartial = false)
    {
        if (destinationLength == 0)
        {
            return 0;
        }

        var destination = new Span<byte>(destinationPointer + NumberOfBytesWritten, Math.Min(destinationLength - NumberOfBytesWritten, bytes.Length));
        var bytesToWrite = allowPartial ? bytes[..destination.Length] : bytes;

        bytesToWrite.CopyTo(destination);

        NumberOfBytesWritten += bytesToWrite.Length;

        return bytesToWrite.Length;
    }
}
