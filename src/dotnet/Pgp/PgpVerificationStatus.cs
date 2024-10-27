namespace Proton.Cryptography.Pgp;

public enum PgpVerificationStatus
{
    Ok = 0,
    NotSigned = 1,
    NoVerifier = 2,
    Failed = 3,
    BadContext = 4,
}
