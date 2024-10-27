using Proton.Cryptography.Srp.Interop;

namespace Proton.Cryptography.Srp;

public readonly struct SrpClientHandshake : IDisposable
{
    private readonly GoSrpClientHandshake? _goSrpClientHandshake;

    internal SrpClientHandshake(nint unsafeGoClientHandshakeHandle, byte[] proof, byte[] ephemeral)
    {
        _goSrpClientHandshake = new GoSrpClientHandshake(unsafeGoClientHandshakeHandle);

        Proof = proof;
        Ephemeral = ephemeral;
    }

    public byte[] Proof { get; }

    public byte[] Ephemeral { get; }

    private GoSrpClientHandshake GoSrpClientHandshake => _goSrpClientHandshake ?? throw new InvalidOperationException("Invalid handle");

    public bool TryComputeSharedKey(ReadOnlySpan<byte> serverProof)
    {
        return GoSrpClientHandshake.TryComputeSharedKey(serverProof);
    }

    public void Dispose()
    {
        _goSrpClientHandshake?.Dispose();
    }
}
