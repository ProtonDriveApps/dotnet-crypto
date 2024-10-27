namespace Proton.Cryptography.Pgp;

public interface IVerificationKeyRingSource
{
    PgpKeyRing VerificationKeyRing { get; }
}
