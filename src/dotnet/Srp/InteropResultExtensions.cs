using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Srp;

internal static class InteropResultExtensions
{
    extension(InteropError interopError)
    {
        public void ThrowSrpExceptionIfAny()
        {
            if (!interopError.TryGetMessage(out var message))
            {
                return;
            }

            throw new SrpException(message);
        }
    }
}
