using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Interop;

internal static partial class CMemory
{
    public static unsafe T[] ConvertToArray<T>(void* pointer, nuint length)
        where T : struct
    {
        try
        {
            var array = new T[length];
            var keyIds = new ReadOnlySpan<T>(pointer, (int)length);

            keyIds.CopyTo(array);
            return array;
        }
        finally
        {
            Free(pointer);
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "libc_free")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static unsafe partial void Free(void* pointer);
}
