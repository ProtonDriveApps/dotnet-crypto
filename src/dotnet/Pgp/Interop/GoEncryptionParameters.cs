namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct GoEncryptionParameters
{
    public readonly nuint EncryptionKeysLength;
    public readonly nuint SigningKeysLength;
    public readonly bool HasSessionKey;
    public readonly bool HasSigningContext;
    public readonly bool HasEncryptionTime;
    public readonly bool DetachSignature;
    public readonly bool DetachedSignatureIsEncrypted;
    public readonly bool Utf8;
    public readonly bool Compress;
    public readonly nint* EncryptionKeys;
    public readonly nint* SigningKeys;
    public readonly nint SessionKey;
    public readonly nint SigningContext;
    public readonly long EncryptionTime;
    public readonly nuint PasswordLength;
    public readonly byte* Password;

    public GoEncryptionParameters(
        nint* encryptionKeys,
        nuint encryptionKeysLength,
        nint* signingKeys,
        nuint signingKeysLength,
        PgpSessionKey? sessionKey,
        byte* password,
        nuint passwordLength,
        bool detachSignature,
        bool detachedSignatureIsEncrypted,
        bool compress,
        TimeProvider? timeProviderOverride)
    {
        EncryptionKeys = encryptionKeys;
        EncryptionKeysLength = encryptionKeysLength;

        SigningKeys = signingKeys;
        SigningKeysLength = signingKeysLength;

        if (sessionKey is not null)
        {
            SessionKey = sessionKey.Value.GoSessionKey.DangerousGetHandle();
            HasSessionKey = true;
        }

        Password = password;
        PasswordLength = passwordLength;

        DetachSignature = detachSignature;
        DetachedSignatureIsEncrypted = detachedSignatureIsEncrypted;

        Compress = compress;

        var timeProvider = timeProviderOverride ?? PgpEnvironment.DefaultTimeProviderOverride;

        if (timeProvider is not null)
        {
            HasEncryptionTime = true;
            EncryptionTime = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        }
    }
}
