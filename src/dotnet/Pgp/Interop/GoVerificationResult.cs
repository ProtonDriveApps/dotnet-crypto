using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoVerificationResult : SafeHandleZeroOrMinusOneIsInvalid
{
    public GoVerificationResult(nint handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    public PgpVerificationStatus GetVerificationStatus()
    {
        using var goError = GoGetVerificationStatus(this, out var status);

        return status;
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_result_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoGetVerificationStatus(GoVerificationResult goVerificationResult, out PgpVerificationStatus status);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_result_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);
}
