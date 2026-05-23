using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Srp;

public readonly partial struct SrpClientHandshake : IDisposable
{
    internal SrpClientHandshake(nint foreignHandle, byte[] proof, byte[] ephemeral)
    {
        ForeignHandle = new ForeignSrpClientHandshakeSafeHandle(foreignHandle);
        Proof = proof;
        Ephemeral = ephemeral;
    }

    public byte[] Proof { get; }

    public byte[] Ephemeral { get; }

    private ForeignSrpClientHandshakeSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public bool TryComputeSharedKey(ReadOnlySpan<byte> serverProof)
    {
        using var error = ForeignFunctions.VerifyProof(ForeignHandle, MemoryMarshal.GetReference(serverProof), (nuint)serverProof.Length, out var isValid);
        error.ThrowSrpExceptionIfAny();

        return isValid;
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_client_handshake_verify_proof")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError VerifyProof(
            ForeignSrpClientHandshakeSafeHandle clientHandshakeHandle,
            in byte serverProof,
            nuint serverProofLength,
            [MarshalAs(UnmanagedType.U1)] out bool isValid);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_client_handshake_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignSrpClientHandshakeSafeHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public ForeignSrpClientHandshakeSafeHandle(nint handle)
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
