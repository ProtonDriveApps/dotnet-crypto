namespace Proton.Cryptography.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe ref struct GoError
{
    public readonly byte* Message;
    public readonly int MessageLength;

    public bool IsSuccess => Message == null;

    public void Dispose()
    {
        if (Message is not null)
        {
            CMemory.Free(Message);
        }
    }
}
