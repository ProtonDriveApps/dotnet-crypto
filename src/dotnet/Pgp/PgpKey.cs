using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpKey : IVerificationKeyRingSource, IEncryptionKeyRingSource
{
    public PgpKey(PgpPrivateKey privateKey)
    {
        GoKey = privateKey.GoKey;
    }

    public PgpKey(PgpPublicKey privateKey)
    {
        GoKey = privateKey.GoKey;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    internal GoKey GoKey { get; }

    public static implicit operator PgpKey(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKey(PgpPublicKey publicKey) => new(publicKey);
}
