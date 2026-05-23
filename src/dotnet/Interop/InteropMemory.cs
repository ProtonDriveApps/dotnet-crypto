using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Interop;

internal static partial class InteropMemory
{
    public static unsafe T[] CopyToArrayAndFree<T>(void* pointer, nuint length)
        where T : struct
    {
        try
        {
            return new ReadOnlySpan<T>(pointer, (int)length).ToArray();
        }
        finally
        {
            Free(pointer);
        }
    }

    [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "interop_memory_free")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static unsafe partial void Free(void* pointer);
}
