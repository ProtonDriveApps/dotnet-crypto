using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpVerificationContext : IDisposable
{
    private PgpVerificationContext(nint foreignHandle)
    {
        ForeignHandle = new ForeignVerificationContextHandle(foreignHandle);
    }

    private ForeignVerificationContextHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static unsafe PgpVerificationContext Create(string value, bool isRequired = true, DateTimeOffset? requiredAfter = null)
    {
        var valueUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(value.Length);
        var valueUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(valueUtf8BytesMaxLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[valueUtf8BytesMaxLength];

        nint verificationContextHandle;
        using (heapMemoryOwner)
        {
            var valueUtf8BytesLength = Encoding.UTF8.GetBytes(value, valueUtf8Bytes);

            verificationContextHandle = ForeignFunctions.Create(
                MemoryMarshal.GetReference(valueUtf8Bytes),
                (nuint)valueUtf8BytesLength,
                isRequired,
                requiredAfter?.ToUnixTimeMilliseconds() ?? 0);
        }

        return new PgpVerificationContext(verificationContextHandle);
    }

    public string GetValue()
    {
        ForeignFunctions.GetValue(ForeignHandle, out var value);
        return value;
    }

    public bool IsRequired()
    {
        return ForeignFunctions.IsRequired(ForeignHandle);
    }

    public DateTimeOffset IsRequiredAfter()
    {
        return DateTimeOffset.FromUnixTimeMilliseconds(ForeignFunctions.IsRequiredAfter(ForeignHandle));
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial nint Create(in byte value, nuint valueLength, [MarshalAs(UnmanagedType.U1)] bool isRequired, long requiredAfter);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_get_value")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial void GetValue(
            ForeignVerificationContextHandle verificationContextHandle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] out string value);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_is_required")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.U1)]
        public static unsafe partial bool IsRequired(ForeignVerificationContextHandle verificationContextHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_is_required_after")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial long IsRequiredAfter(ForeignVerificationContextHandle verificationContextHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignVerificationContextHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
    {
        public ForeignVerificationContextHandle(nint handle)
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
