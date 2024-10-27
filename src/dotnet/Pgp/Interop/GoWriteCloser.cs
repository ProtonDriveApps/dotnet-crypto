using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoWriteCloser() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    public GoWriteCloser(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public int Write(in byte buffer, nuint bufferLength)
    {
        using var goError = GoWrite(this, buffer, bufferLength, out var numberOfBytesWritten);
        goError.ThrowIfFailure();

        return (int)numberOfBytesWritten;
    }

    public void WriteEnd()
    {
        using var goError = GoClose(this);
        goError.ThrowIfFailure();
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_write_closer_write")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoWrite(GoWriteCloser goWriteCloser, in byte buffer, nuint bufferLength, out nint numberOfBytesWritten);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_write_closer_close")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoClose(GoWriteCloser goWriteCloser);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_write_closer_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);
}
