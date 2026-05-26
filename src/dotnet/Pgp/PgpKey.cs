using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents an OpenPGP key that can be used for encryption and verification operations.
/// </summary>
public readonly struct PgpKey : IVerificationKeyRingSource, IEncryptionKeyRingSource
{
    public PgpKey(PgpPrivateKey privateKey)
    {
        GoKey = privateKey.GoKey;
    }

    public PgpKey(PgpPublicKey publicKey)
    {
        GoKey = publicKey.GoKey;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    internal GoKey GoKey { get; }

    public static implicit operator PgpKey(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKey(PgpPublicKey publicKey) => new(publicKey);
}
