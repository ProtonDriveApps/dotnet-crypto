using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct InteropEncryptionParameters
{
    public readonly byte Profile;
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
    public readonly ulong EncryptionTime;
    public readonly ulong MessageSizeHint;
    public readonly nuint PasswordLength;
    public readonly byte* Password;

    public InteropEncryptionParameters(
        PgpProfile profile,
        nint* encryptionKeys,
        nuint encryptionKeysLength,
        nint* signingKeys,
        nuint signingKeysLength,
        PgpSessionKey? sessionKeyOrNull,
        byte* password,
        nuint passwordLength,
        bool detachSignature,
        bool detachedSignatureIsEncrypted,
        bool compress,
        long? aeadStreamingChunkLength,
        TimeProvider? timeProviderOverride)
    {
        Profile = (byte)profile;

        EncryptionKeys = encryptionKeys;
        EncryptionKeysLength = encryptionKeysLength;

        SigningKeys = signingKeys;
        SigningKeysLength = signingKeysLength;

        if (sessionKeyOrNull is { } sessionKey)
        {
            SessionKey = ((IForeignHandleProxy)sessionKey).ForeignHandle.DangerousGetHandle();
            HasSessionKey = true;
        }

        Password = password;
        PasswordLength = passwordLength;

        DetachSignature = detachSignature;
        DetachedSignatureIsEncrypted = detachedSignatureIsEncrypted;

        Compress = compress;

        MessageSizeHint = checked((ulong)(aeadStreamingChunkLength ?? PgpConfiguration.DefaultAeadStreamingChunkLength));

        var timeProvider = timeProviderOverride ?? PgpConfiguration.DefaultTimeProviderOverride;

        if (timeProvider is not null)
        {
            HasEncryptionTime = true;
            EncryptionTime = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        }
    }
}
