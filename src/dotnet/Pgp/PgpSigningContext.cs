using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp;

internal sealed partial class PgpSigningContext : IDisposable
{
    private readonly GoSigningContextHandle _goHandle;

    private PgpSigningContext(GoSigningContextHandle goHandle)
    {
        _goHandle = goHandle;
    }

    public static unsafe PgpSigningContext Create(string value, bool isCritical = false)
    {
        var valueUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(value.Length);
        var valueUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(valueUtf8BytesMaxLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[valueUtf8BytesMaxLength];

        nint goHandle;
        using (heapMemoryOwner)
        {
            var valueUtf8BytesLength = Encoding.UTF8.GetBytes(value, valueUtf8Bytes);

            goHandle = GoCreate(MemoryMarshal.GetReference(valueUtf8Bytes), (nuint)valueUtf8BytesLength, isCritical);
        }

        return new PgpSigningContext(new GoSigningContextHandle(goHandle));
    }

    public void Dispose()
    {
        _goHandle.Dispose();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_signing_context_new")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial nint GoCreate(in byte value, nuint valueLength, [MarshalAs(UnmanagedType.U1)] bool isCritical);

    private sealed partial class GoSigningContextHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public GoSigningContextHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            ReleaseHandle(handle);

            return true;
        }

        [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_signing_context_new_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        private static partial void ReleaseHandle(nint handle);
    }
}
