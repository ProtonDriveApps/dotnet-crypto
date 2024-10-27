using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct GoExternalReader(GCHandle streamHandle)
{
    private readonly nint _streamHandlePointer = GCHandle.ToIntPtr(streamHandle);
    private readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, ErrorCode*, long> _writeFunctionPointer = &Read;

    private enum ErrorCode
    {
        Error = -1,
        NoError = 0,
        EndOfFile = 1,
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static long Read(nint streamHandlePointer, byte* buffer, nuint bufferLength, ErrorCode* errorCode)
    {
        if (GCHandle.FromIntPtr(streamHandlePointer).Target is not Stream stream)
        {
            *errorCode = ErrorCode.Error;
            return 0;
        }

        try
        {
            var numberOfBytesRead = stream.Read(new Span<byte>(buffer, (int)bufferLength));
            *errorCode = numberOfBytesRead > 0 ? ErrorCode.NoError : ErrorCode.EndOfFile;
            return numberOfBytesRead;
        }
        catch
        {
            *errorCode = ErrorCode.Error;
            return 0;
        }
    }
}
