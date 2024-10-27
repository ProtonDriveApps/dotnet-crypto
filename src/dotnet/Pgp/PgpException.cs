namespace Proton.Cryptography.Pgp;

public sealed class PgpException : Exception
{
    public PgpException()
    {
    }

    public PgpException(string? message)
        : base(message)
    {
    }

    public PgpException(string? message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
