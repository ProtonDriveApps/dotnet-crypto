namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe ref struct GoDecryptionParameters
{
    public readonly nuint DecryptionKeysLength;
    public readonly nuint VerificationKeysLength;
    public readonly nuint PasswordLength;
    public readonly nuint DetachedSignatureLength;
    public readonly bool HasSessionKey;
    public readonly bool HasVerificationContext;
    public readonly bool HasVerificationTime;
    public readonly bool IsUtf8;
    public readonly bool DetachedSignatureIsEncrypted;
    public readonly bool DetachedSignatureIsArmored;
    public readonly nint* DecryptionKeys;
    public readonly nint* VerificationKeys;
    public readonly nint SessionKey;
    public readonly nint VerificationContext;
    public readonly long VerificationTime;
    public readonly byte* Password;
    public readonly byte* DetachedSignature;

    public GoDecryptionParameters(
        nint* decryptionKeys,
        nuint decryptionKeysLength,
        nint* verificationKeys,
        nuint verificationKeysLength,
        PgpSessionKey? sessionKey,
        byte* password,
        nuint passwordLength,
        byte* detachedSignature,
        nuint detachedSignatureLength,
        PgpEncoding detachedSignatureEncoding,
        EncryptionState detachedSignatureEncryptionState,
        TimeProvider? timeProviderOverride)
    {
        DecryptionKeys = decryptionKeys;
        DecryptionKeysLength = decryptionKeysLength;

        VerificationKeys = verificationKeys;
        VerificationKeysLength = verificationKeysLength;

        if (sessionKey is not null)
        {
            SessionKey = sessionKey.Value.GoSessionKey.DangerousGetHandle();
            HasSessionKey = true;
        }

        Password = password;
        PasswordLength = passwordLength;

        DetachedSignature = detachedSignature;
        DetachedSignatureLength = detachedSignatureLength;

        DetachedSignatureIsArmored = detachedSignatureEncoding == PgpEncoding.AsciiArmor;
        DetachedSignatureIsEncrypted = detachedSignatureEncryptionState == EncryptionState.Encrypted;

        var timeProvider = timeProviderOverride ?? PgpEnvironment.DefaultTimeProviderOverride;

        if (timeProvider is not null)
        {
            HasVerificationTime = true;
            VerificationTime = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        }
    }
}
