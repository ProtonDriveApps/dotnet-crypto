namespace Proton.Cryptography.Pgp;

public readonly struct PgpSignatureDetails
{
    internal PgpSignatureDetails(ulong keyId)
    {
        KeyId = keyId;
    }

    public ulong KeyId { get; }
}
