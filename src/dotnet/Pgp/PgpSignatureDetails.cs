namespace Proton.Cryptography.Pgp;

public sealed class PgpSignatureDetails
{
    public PgpSignatureDetails(long keyId)
    {
        KeyId = keyId;
    }

    public long KeyId { get; }
}
