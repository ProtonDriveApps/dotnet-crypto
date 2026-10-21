using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpVerificationContext : IDisposable, IForeignHandleProxy
{
    private PgpVerificationContext(nint foreignHandle)
    {
        ForeignHandle = new ForeignVerificationContextHandle(foreignHandle);
    }

    SafeHandle IForeignHandleProxy.ForeignHandle => ForeignHandle;

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

            using var error = ForeignFunctions.Create(
                MemoryMarshal.GetReference(valueUtf8Bytes),
                (nuint)valueUtf8BytesLength,
                isRequired,
                checked((ulong)(requiredAfter?.ToUnixTimeSeconds() ?? 0)),
                out verificationContextHandle);

            error.ThrowPgpExceptionIfAny();
        }

        return new PgpVerificationContext(verificationContextHandle);
    }

    public string GetValue()
    {
        var error = ForeignFunctions.GetValue(ForeignHandle, out var value);
        error.ThrowPgpExceptionIfAny();

        return value;
    }

    public bool IsRequired()
    {
        var error = ForeignFunctions.IsRequired(ForeignHandle, out var isRequired);
        error.ThrowPgpExceptionIfAny();

        return isRequired;
    }

    public DateTimeOffset IsRequiredAfter()
    {
        var error = ForeignFunctions.IsRequiredAfter(ForeignHandle, out var requiredAfter);
        error.ThrowPgpExceptionIfAny();

        return DateTimeOffset.FromUnixTimeMilliseconds(checked((long)requiredAfter));
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Create(
            in byte value,
            nuint valueLength,
            [MarshalAs(UnmanagedType.U1)] bool isRequired,
            ulong requiredAfter,
            out nint verificationContextHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_get_value")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError GetValue(
            ForeignVerificationContextHandle verificationContextHandle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] out string value);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_is_required")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError IsRequired(
            ForeignVerificationContextHandle verificationContextHandle,
            [MarshalAs(UnmanagedType.U1)] out bool isRequired);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_context_is_required_after")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError IsRequiredAfter(ForeignVerificationContextHandle verificationContextHandle, out ulong requiredAfter);

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
