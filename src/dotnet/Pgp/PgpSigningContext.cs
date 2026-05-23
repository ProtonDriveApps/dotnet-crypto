using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpSigningContext : IDisposable
{
    private PgpSigningContext(ForeignSigningContextSafeHandle foreignHandle)
    {
        ForeignHandle = foreignHandle;
    }

    private ForeignSigningContextSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static unsafe PgpSigningContext Create(string value, bool isCritical = false)
    {
        var valueUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(value.Length);
        var valueUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(valueUtf8BytesMaxLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[valueUtf8BytesMaxLength];

        nint signingContextHandle;
        using (heapMemoryOwner)
        {
            var valueUtf8BytesLength = Encoding.UTF8.GetBytes(value, valueUtf8Bytes);

            signingContextHandle = ForeignFunctions.Create(MemoryMarshal.GetReference(valueUtf8Bytes), (nuint)valueUtf8BytesLength, isCritical);
        }

        return new PgpSigningContext(new ForeignSigningContextSafeHandle(signingContextHandle));
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_signing_context_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial nint Create(in byte value, nuint valueLength, [MarshalAs(UnmanagedType.U1)] bool isCritical);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_signing_context_new_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignSigningContextSafeHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public ForeignSigningContextSafeHandle(nint handle)
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
