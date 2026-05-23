using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpVerificationResult : IDisposable
{
    internal PgpVerificationResult(nint foreignHandle)
    {
        ForeignHandle = new ForeignVerificationResultSafeHandle(foreignHandle);
    }

    public PgpVerificationStatus Status
    {
        get
        {
            using var error = ForeignFunctions.GetVerificationStatus(ForeignHandle, out var status);

            if (status == PgpVerificationStatus.Ok)
            {
                error.ThrowPgpExceptionIfAny();
            }

            return status;
        }
    }

    private ForeignVerificationResultSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public PgpSignatureDetails GetSignatureDetails()
    {
        throw new NotImplementedException();
    }

    public string[] GetAllSignatures()
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_result_error")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError GetVerificationStatus(
            ForeignVerificationResultSafeHandle verificationResultHandle,
            out PgpVerificationStatus status);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_result_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignVerificationResultSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ForeignVerificationResultSafeHandle(nint handle)
            : base(ownsHandle: true)
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
