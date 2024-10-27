using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Srp.Interop;

internal sealed partial class GoSrpClientHandshake() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    public GoSrpClientHandshake(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public bool TryComputeSharedKey(ReadOnlySpan<byte> serverProof)
    {
        using var goError = GoVerifyProof(this, MemoryMarshal.GetReference(serverProof), (nuint)serverProof.Length, out var isValid);
        goError.ThrowIfFailure();

        return isValid;
    }

    protected override bool ReleaseHandle()
    {
        ReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_client_handshake_verify_proof")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoVerifyProof(
        GoSrpClientHandshake goClientHandshake,
        in byte serverProof,
        nuint serverProofLength,
        [MarshalAs(UnmanagedType.U1)] out bool isValid);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_client_handshake_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void ReleaseHandle(nint handle);
}
