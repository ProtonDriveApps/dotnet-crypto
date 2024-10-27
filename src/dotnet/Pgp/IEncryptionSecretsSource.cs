namespace Proton.Cryptography.Pgp;

public interface IEncryptionSecretsSource
{
    EncryptionSecrets EncryptionSecrets { get; }
}
