using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal static class InteropResultExtensions
{
    extension(InteropError interopError)
    {
        public void ThrowPgpExceptionIfAny()
        {
            if (!interopError.TryGetMessage(out var message))
            {
                return;
            }

            throw new PgpException(message);
        }
    }
}
