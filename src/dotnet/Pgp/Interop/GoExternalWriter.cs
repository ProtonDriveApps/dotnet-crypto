using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct GoExternalWriter
{
    public readonly nint OutputHandle;
    public readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, long> WriteFunctionPointer;

    public GoExternalWriter(GCHandle outputStreamHandle)
    {
        OutputHandle = GCHandle.ToIntPtr(outputStreamHandle);
        WriteFunctionPointer = &WriteToStream;
    }

    public GoExternalWriter(SpanWriter* outputWriter)
    {
        OutputHandle = new nint(outputWriter);
        WriteFunctionPointer = &WriteToMemory;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static long WriteToStream(nint outputHandle, byte* inputPointer, nuint inputLength)
    {
        if (GCHandle.FromIntPtr(outputHandle).Target is not Stream outputStream)
        {
            return -1;
        }

        try
        {
            outputStream.Write(new Span<byte>(inputPointer, (int)inputLength));
            return (long)inputLength;
        }
        catch
        {
            return -1;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static long WriteToMemory(nint outputHandle, byte* inputPointer, nuint inputLength)
    {
        try
        {
            ref var outputWriter = ref Unsafe.AsRef<SpanWriter>(outputHandle.ToPointer());

            return outputWriter.Write(new Span<byte>(inputPointer, (int)inputLength));
        }
        catch
        {
            return -1;
        }
    }
}
