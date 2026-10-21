using System.Runtime.CompilerServices;

namespace Proton.Cryptography.Interop;

internal static class WorkDispatcher
{
    internal static unsafe delegate* unmanaged[Cdecl]<InteropWorkTask, byte> Pointer => &DispatchWork;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static byte DispatchWork(InteropWorkTask task)
    {
        Task.Factory.StartNew(
            static state =>
            {
                unsafe
                {
                    var taskFromState = (InteropWorkTask)state!;
                    taskFromState.Function(taskFromState.Arguments);
                }
            },
            task,
            TaskCreationOptions.LongRunning);

        return 1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly unsafe struct InteropWorkTask
    {
        public readonly delegate* unmanaged[Cdecl]<nint, void> Function;
        public readonly nint Arguments;
    }
}
