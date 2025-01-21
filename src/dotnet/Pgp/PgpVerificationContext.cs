using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpVerificationContext : IDisposable
{
    private readonly GoVerificationContextHandle _goHandle;

    private PgpVerificationContext(GoVerificationContextHandle goHandle)
    {
        _goHandle = goHandle;
    }

    public static unsafe PgpVerificationContext Create(string value, bool isRequired = true, DateTimeOffset? requiredAfter = null)
    {
        var valueUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(value.Length);
        var valueUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(valueUtf8BytesMaxLength, out var heapMemory, out var heapMemoryOwner)
            ? heapMemory.Span
            : stackalloc byte[valueUtf8BytesMaxLength];

        nint goHandle;
        using (heapMemoryOwner)
        {
            var valueUtf8BytesLength = Encoding.UTF8.GetBytes(value, valueUtf8Bytes);

            goHandle = GoCreate(
                MemoryMarshal.GetReference(valueUtf8Bytes),
                (nuint)valueUtf8BytesLength,
                isRequired,
                requiredAfter?.ToUnixTimeMilliseconds() ?? 0);
        }

        return new PgpVerificationContext(new GoVerificationContextHandle(goHandle));
    }

    public string GetValue()
    {
        GoGetValue(_goHandle, out var value);
        return value;
    }

    public bool IsRequired()
    {
        return GoIsRequired(_goHandle);
    }

    public DateTimeOffset IsRequiredAfter()
    {
        return DateTimeOffset.FromUnixTimeMilliseconds(GoIsRequiredAfter(_goHandle));
    }

    public void Dispose()
    {
        _goHandle.Dispose();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_context_new")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial nint GoCreate(in byte value, nuint valueLength, [MarshalAs(UnmanagedType.U1)] bool isRequired, long requiredAfter);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_context_get_value")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoGetValue(GoVerificationContextHandle verificationContextHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] out string value);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_context_is_required")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [return: MarshalAs(UnmanagedType.U1)]
    private static unsafe partial bool GoIsRequired(GoVerificationContextHandle verificationContextHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_context_is_required_after")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial long GoIsRequiredAfter(GoVerificationContextHandle verificationContextHandle);

    private sealed partial class GoVerificationContextHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public GoVerificationContextHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            ReleaseHandle(handle);

            return true;
        }

        [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_context_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        private static partial void ReleaseHandle(nint handle);
    }
}
