using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal readonly partial struct ForeignReader(nint foreignHandle) : IDisposable
{
    private ForeignReaderSafeHandle ForeignHandle { get => field ?? throw new InvalidOperationException("Invalid handle"); } = new(foreignHandle);

    public int Read(ReadOnlySpan<byte> buffer)
    {
        using var error = ForeignFunctions.Read(ForeignHandle, MemoryMarshal.GetReference(buffer), (nuint)buffer.Length, out var numberOfBytesRead);
        error.ThrowPgpExceptionIfAny();

        return (int)numberOfBytesRead;
    }

    public PgpVerificationResult GetVerificationResult()
    {
        using var error = ForeignFunctions.GetVerificationResult(ForeignHandle, out var verificationResultHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpVerificationResult(verificationResultHandle);
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_reader_read")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Read(ForeignReaderSafeHandle readerHandle, in byte buffer, nuint bufferLength, out nuint numberOfBytesRead);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_verification_reader_get_verify_result")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError GetVerificationResult(ForeignReaderSafeHandle outputReaderHandle, out nint verificationResultHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_go_reader_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignReaderSafeHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public ForeignReaderSafeHandle(nint handle)
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
