using Proton.Cryptography.Srp.Interop;

namespace Proton.Cryptography.Srp;

public readonly struct SrpServerHandshake : IDisposable
{
    private readonly GoSrpServer? _goSrpServer;
    private readonly int _bitLength;

    private SrpServerHandshake(GoSrpServer goSrpServer, byte[] ephemeral, int bitLength)
    {
        _goSrpServer = goSrpServer;
        Ephemeral = ephemeral;
        _bitLength = bitLength;
    }

    public byte[] Ephemeral { get; }

    private GoSrpServer GoSrpServer => _goSrpServer ?? throw new InvalidOperationException("Invalid handle");

    public static SrpServerHandshake Generate(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> verifier, int bitLength)
    {
        return Generate(modulus, verifier, [], bitLength);
    }

    public static SrpServerHandshake Generate(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> verifier, ReadOnlySpan<byte> secret, int bitLength)
    {
        var ephemeral = new byte[bitLength / 8];

        var goSrpServer = GoSrpServer.Generate(modulus, verifier, ephemeral, MemoryMarshal.GetReference(secret), secret.Length, bitLength);

        return new SrpServerHandshake(goSrpServer, ephemeral, bitLength);
    }

    public bool TryComputeSharedKey(ReadOnlySpan<byte> clientProof, ReadOnlySpan<byte> clientEphemeral, [MaybeNullWhen(false)] out byte[] proof)
    {
        return GoSrpServer.TryComputeSharedKey(clientProof, clientEphemeral, _bitLength, out proof);
    }

    public void Dispose()
    {
        _goSrpServer?.Dispose();
    }
}
