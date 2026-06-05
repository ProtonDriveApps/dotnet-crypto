using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class ForeignKeySafeHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
{
    public ForeignKeySafeHandle(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public ref nint DangerousGetHandleRef() => ref handle;

    protected override bool ReleaseHandle()
    {
        ForeignFunctions.ReleaseHandle(handle);

        return true;
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint keyHandle);
    }
}
