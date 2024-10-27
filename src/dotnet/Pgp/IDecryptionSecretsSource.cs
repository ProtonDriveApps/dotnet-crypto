namespace Proton.Cryptography.Pgp;

public interface IDecryptionSecretsSource
{
    DecryptionSecrets DecryptionSecrets { get; }
}
