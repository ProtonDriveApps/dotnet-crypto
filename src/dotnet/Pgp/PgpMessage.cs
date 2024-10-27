using System.Buffers;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpMessage : IDisposable
{
    private readonly GoMessage? _goMessage;
    private readonly MemoryHandle? _messageMemoryHandle;

    private PgpMessage(GoMessage goMessage, MemoryHandle messageMemoryHandle)
    {
        _goMessage = goMessage;
        _messageMemoryHandle = messageMemoryHandle;
    }

    private GoMessage GoMessage => _goMessage ?? throw new InvalidOperationException("Invalid handle");

    public static unsafe PgpMessage Open(ReadOnlyMemory<byte> message, PgpEncoding encoding = default)
    {
        var messageMemoryHandle = message.Pin();

        try
        {
            return new PgpMessage(
                GoMessage.Open((byte*)messageMemoryHandle.Pointer, (nuint)message.Length, encoding == PgpEncoding.AsciiArmor),
                messageMemoryHandle);
        }
        catch
        {
            messageMemoryHandle.Dispose();
            throw;
        }
    }

    public long[] GetEncryptionKeyIds()
    {
        return GoMessage.GetEncryptionKeyIds();
    }

    public long[] GetSigningKeyIds()
    {
        return GoMessage.GetSigningKeyIds();
    }

    public int GetKeyPacketsLength()
    {
        return (int)GoMessage.GetKeyPacketsLength();
    }

    public void Dispose()
    {
        _goMessage?.Dispose();
        _messageMemoryHandle?.Dispose();
    }
}
