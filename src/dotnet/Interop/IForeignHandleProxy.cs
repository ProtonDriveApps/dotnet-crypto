namespace Proton.Cryptography.Interop;

internal interface IForeignHandleProxy
{
    SafeHandle ForeignHandle { get; }
}
