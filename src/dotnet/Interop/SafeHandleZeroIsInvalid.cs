namespace Proton.Cryptography.Interop;

public abstract class SafeHandleZeroIsInvalid(bool ownsHandle) : SafeHandle(nint.Zero, ownsHandle)
{
    public override bool IsInvalid => handle == nint.Zero;
}
