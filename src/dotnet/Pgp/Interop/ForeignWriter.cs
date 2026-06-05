using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal readonly partial struct ForeignWriter(nint foreignHandle) : IDisposable
{
    private ForeignWriterSafeHandle ForeignHandle { get => field ?? throw new InvalidOperationException("Invalid handle"); } = new(foreignHandle);

    public int Write(ReadOnlySpan<byte> buffer)
    {
        using var error = ForeignFunctions.Write(ForeignHandle, MemoryMarshal.GetReference(buffer), (nuint)buffer.Length, out var numberOfBytesWritten);
        error.ThrowPgpExceptionIfAny();

        return (int)numberOfBytesWritten;
    }

    public void WriteEnd()
    {
        using var error = ForeignFunctions.Close(ForeignHandle);
        error.ThrowPgpExceptionIfAny();
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_write_closer_write")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Write(ForeignWriterSafeHandle writerHandle, in byte buffer, nuint bufferLength, out nint numberOfBytesWritten);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_write_closer_close")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Close(ForeignWriterSafeHandle writerHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_write_closer_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint writerHandle);
    }

    private sealed class ForeignWriterSafeHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
    {
        public ForeignWriterSafeHandle(nint handle)
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
