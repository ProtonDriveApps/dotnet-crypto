using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoReader() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    public GoReader(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public int Read(in byte buffer, nuint bufferLength)
    {
        using var goError = GoRead(this, buffer, bufferLength, out var numberOfBytesRead);
        goError.ThrowIfFailure();

        return (int)numberOfBytesRead;
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_reader_read")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoRead(GoReader goReader, in byte buffer, nuint bufferLength, out nuint numberOfBytesRead);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_go_reader_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);
}
