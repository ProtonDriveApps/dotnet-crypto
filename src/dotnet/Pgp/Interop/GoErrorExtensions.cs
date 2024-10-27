using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal static class GoErrorExtensions
{
    public static unsafe void ThrowIfFailure(this GoError goError)
    {
        if (goError.Message is null)
        {
            return;
        }

        var messageString = Encoding.UTF8.GetString(goError.Message, goError.MessageLength);

        throw new PgpException(messageString);
    }
}
