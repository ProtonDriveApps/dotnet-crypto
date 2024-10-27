namespace Proton.Cryptography.Pgp;

public interface IEncryptionKeyRingSource : IEncryptionSecretsSource
{
    PgpKeyRing EncryptionKeyRing { get; }

    EncryptionSecrets IEncryptionSecretsSource.EncryptionSecrets => EncryptionKeyRing;
}
