using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Srp.Interop;

internal sealed partial class GoSrpServer() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    private GoSrpServer(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public static unsafe GoSrpServer Generate(
        ReadOnlySpan<byte> modulus,
        ReadOnlySpan<byte> verifier,
        byte[] ephemeralBuffer,
        in byte secretPointer,
        int secretLength,
        int bitLength)
    {
        fixed (byte* modulusPointer = modulus)
        {
            fixed (byte* verifierPointer = verifier)
            {
                var parameters = new GoServerCreationParameters(modulusPointer, (nuint)modulus.Length, verifierPointer, (nuint)verifier.Length, bitLength);

                using var goError = GoGenerateServerHandshake(
                    parameters,
                    secretPointer,
                    secretLength,
                    MemoryMarshal.GetArrayDataReference(ephemeralBuffer),
                    (nuint)ephemeralBuffer.Length,
                    out var unsafeGoServerHandle);

                goError.ThrowIfFailure();

                return new GoSrpServer(unsafeGoServerHandle);
            }
        }
    }

    public bool TryComputeSharedKey(
        ReadOnlySpan<byte> clientProof,
        ReadOnlySpan<byte> clientEphemeral,
        int bitLength,
        [MaybeNullWhen(false)] out byte[] proof)
    {
        var serverProof = new byte[bitLength / 8];

        using var result = GoComputeExchange(
            this,
            MemoryMarshal.GetReference(clientProof),
            clientProof.Length,
            MemoryMarshal.GetReference(clientEphemeral),
            (nuint)clientEphemeral.Length,
            MemoryMarshal.GetArrayDataReference(serverProof),
            (nuint)serverProof.Length);

        if (!result.IsSuccess)
        {
            proof = null;
            return false;
        }

        proof = serverProof;
        return true;
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_server_generate_handshake")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoGenerateServerHandshake(
        in GoServerCreationParameters parameters,
        in byte secret,
        int secretLength,
        in byte ephemeralBuffer,
        nuint ephemeralBufferLength,
        out nint serverHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_server_compute_exchange")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoComputeExchange(
        GoSrpServer goSrpServer,
        in byte clientProof,
        int clientProofLength,
        in byte clientEphemeral,
        nuint clientEphemeralLength,
        in byte proofBuffer,
        nuint proofBufferLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_server_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe readonly struct GoServerCreationParameters(byte* modulus, nuint modulusLength, byte* verifier, nuint verifierLength, int bitLength)
    {
        public readonly nuint ModulusLength = modulusLength;
        public readonly nuint VerifierLength = verifierLength;
        public readonly byte* Modulus = modulus;
        public readonly byte* Verifier = verifier;
        public readonly int BitLength = bitLength;
    }
}
