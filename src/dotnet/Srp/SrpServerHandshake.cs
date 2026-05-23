using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Srp;

public readonly partial struct SrpServerHandshake : IDisposable
{
    private readonly int _bitLength;

    private SrpServerHandshake(nint foreignHandle, byte[] ephemeral, int bitLength)
    {
        ForeignHandle = new ForeignSrpServerHandshakeSafeHandle(foreignHandle);
        Ephemeral = ephemeral;
        _bitLength = bitLength;
    }

    public byte[] Ephemeral { get; }

    private ForeignSrpServerHandshakeSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static SrpServerHandshake Generate(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> verifier, int bitLength)
    {
        return Generate(modulus, verifier, ReadOnlySpan<byte>.Empty, bitLength);
    }

    public static unsafe SrpServerHandshake Generate(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> verifier, ReadOnlySpan<byte> secret, int bitLength)
    {
        var ephemeral = new byte[bitLength / 8];

        fixed (byte* modulusPointer = modulus)
        {
            fixed (byte* verifierPointer = verifier)
            {
                var parameters = new InteropServerCreationParameters(modulusPointer, (nuint)modulus.Length, verifierPointer, (nuint)verifier.Length, bitLength);

                using var error = ForeignFunctions.Generate(
                    parameters,
                    MemoryMarshal.GetReference(secret),
                    secret.Length,
                    MemoryMarshal.GetArrayDataReference(ephemeral),
                    (nuint)ephemeral.Length,
                    out var serverHandshakeHandle);

                error.ThrowSrpExceptionIfAny();

                return new SrpServerHandshake(serverHandshakeHandle, ephemeral, bitLength);
            }
        }
    }

    public bool TryComputeSharedKey(ReadOnlySpan<byte> clientProof, ReadOnlySpan<byte> clientEphemeral, [MaybeNullWhen(false)] out byte[] proof)
    {
        var serverProof = new byte[_bitLength / 8];

        using var result = ForeignFunctions.ComputeExchange(
            ForeignHandle,
            MemoryMarshal.GetReference(clientProof),
            clientProof.Length,
            MemoryMarshal.GetReference(clientEphemeral),
            (nuint)clientEphemeral.Length,
            MemoryMarshal.GetArrayDataReference(serverProof),
            (nuint)serverProof.Length);

        if (result.Any)
        {
            proof = null;
            return false;
        }

        proof = serverProof;
        return true;
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe readonly struct InteropServerCreationParameters(byte* modulus, nuint modulusLength, byte* verifier, nuint verifierLength, int bitLength)
    {
        public readonly nuint ModulusLength = modulusLength;
        public readonly nuint VerifierLength = verifierLength;
        public readonly byte* Modulus = modulus;
        public readonly byte* Verifier = verifier;
        public readonly int BitLength = bitLength;
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_server_generate_handshake")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Generate(
            in InteropServerCreationParameters parameters,
            in byte secret,
            int secretLength,
            in byte ephemeralBuffer,
            nuint ephemeralBufferLength,
            out nint serverHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_server_compute_exchange")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError ComputeExchange(
            ForeignSrpServerHandshakeSafeHandle srpServerHandle,
            in byte clientProof,
            int clientProofLength,
            in byte clientEphemeral,
            nuint clientEphemeralLength,
            in byte proofBuffer,
            nuint proofBufferLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_server_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignSrpServerHandshakeSafeHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public ForeignSrpServerHandshakeSafeHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            ForeignFunctions.ReleaseHandle(handle);

            return true;
        }
    }
}
