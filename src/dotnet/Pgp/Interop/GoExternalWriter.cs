using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct GoExternalWriter
{
    public readonly nint OutputHandle;
    public readonly delegate* unmanaged[Cdecl]<nint, byte*, nuint, long> WriteFunctionPointer;

    private GoExternalWriter(nint outputHandle, delegate* unmanaged[Cdecl]<nint, byte*, nuint, long> writeFunctionPointer)
    {
        OutputHandle = outputHandle;
        WriteFunctionPointer = writeFunctionPointer;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static GoExternalWriter FromStreamHandle(GCHandle streamHandle)
    {
        return new GoExternalWriter(GCHandle.ToIntPtr(streamHandle), &WriteToStream);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static GoExternalWriter FromSpanWriter(SpanWriter* spanWriter)
    {
        return new GoExternalWriter(new nint(spanWriter), &WriteToSpan);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static long WriteToStream(nint streamHandle, byte* inputPointer, nuint inputLength)
    {
        if (GCHandle.FromIntPtr(streamHandle).Target is not Stream outputStream)
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
    private static long WriteToSpan(nint outputHandle, byte* inputPointer, nuint inputLength)
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
