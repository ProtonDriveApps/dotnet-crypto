namespace Proton.Cryptography.Pgp;

public readonly struct PgpSignatureDetails
{
    internal PgpSignatureDetails(long keyId)
    {
        KeyId = keyId;
    }

    public long KeyId { get; }
}
