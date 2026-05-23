namespace Proton.Cryptography.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe ref struct InteropError
{
    private readonly byte* _message;
    private readonly int _messageLength;

    public bool Any => _message != null;

    public bool TryGetMessage([MaybeNullWhen(false)] out string message)
    {
        if (_message == null)
        {
            message = null;
            return false;
        }

        message = Encoding.UTF8.GetString(new ReadOnlySpan<byte>(_message, _messageLength));
        return true;
    }

    public void Dispose()
    {
        if (_message is not null)
        {
            InteropMemory.Free(_message);
        }
    }
}
