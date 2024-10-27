namespace Proton.Cryptography.Pgp;

public interface ISigningKeyRingSource
{
    PgpPrivateKeyRing SigningKeyRing { get; }
}
