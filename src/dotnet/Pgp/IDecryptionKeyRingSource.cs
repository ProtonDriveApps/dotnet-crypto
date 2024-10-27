namespace Proton.Cryptography.Pgp;

public interface IDecryptionKeyRingSource : IDecryptionSecretsSource
{
    PgpPrivateKeyRing DecryptionKeyRing { get; }

    DecryptionSecrets IDecryptionSecretsSource.DecryptionSecrets => DecryptionKeyRing;
}
