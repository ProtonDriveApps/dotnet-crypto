namespace Proton.Cryptography.Pgp.Interop;

internal unsafe struct SpanWriter(byte* pointer, int length)
{
    public int NumberOfBytesWritten;

    public int Write(Span<byte> bytes)
    {
        var output = new Span<byte>(pointer + NumberOfBytesWritten, Math.Min(length - NumberOfBytesWritten, bytes.Length));

        bytes.CopyTo(output);

        NumberOfBytesWritten += output.Length;

        return output.Length;
    }
}
