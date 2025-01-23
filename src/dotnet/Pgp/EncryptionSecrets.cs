namespace Proton.Cryptography.Pgp;

public readonly ref struct EncryptionSecrets
{
    private readonly PgpKeyRing _keyRing;
    private readonly PgpSessionKey? _sessionKey;
    private readonly ReadOnlySpan<byte> _password;

    public EncryptionSecrets(PgpKeyRing keyRing)
        : this(keyRing, null, [])
    {
    }

    public EncryptionSecrets(PgpSessionKey sessionKey)
        : this(default, sessionKey, [])
    {
    }

    public EncryptionSecrets(PgpKeyRing keyRing, PgpSessionKey sessionKey)
        : this(keyRing, sessionKey, [])
    {
    }

    public EncryptionSecrets(ReadOnlySpan<byte> password)
        : this(default, null, password)
    {
    }

    public EncryptionSecrets(PgpKeyRing keyRing, ReadOnlySpan<byte> password)
        : this(keyRing, null, password)
    {
    }

    private EncryptionSecrets(PgpKeyRing keyRing, PgpSessionKey? sessionKey, ReadOnlySpan<byte> password)
    {
        _keyRing = keyRing;
        _sessionKey = sessionKey;
        _password = password;
    }

    public static implicit operator EncryptionSecrets(PgpPrivateKey privateKey)
        => new(new PgpKeyRing(privateKey));

    public static implicit operator EncryptionSecrets(PgpPublicKey publicKey)
        => new(new PgpKeyRing(publicKey));

    public static implicit operator EncryptionSecrets(PgpKey key)
        => new(new PgpKeyRing(key));

    public static implicit operator EncryptionSecrets(PgpKeyRing keyRing)
        => new(keyRing);

    public static implicit operator EncryptionSecrets(PgpSessionKey sessionKey)
        => new(sessionKey);

    public static implicit operator EncryptionSecrets(ReadOnlySpan<byte> password)
        => new(password);

    [UnscopedRef]
    internal void Deconstruct(out PgpKeyRing keyRing, out PgpSessionKey? sessionKey, out ReadOnlySpan<byte> password)
    {
        keyRing = _keyRing;
        sessionKey = _sessionKey;
        password = _password;
    }
}
