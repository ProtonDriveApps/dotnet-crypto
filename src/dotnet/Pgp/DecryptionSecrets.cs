namespace Proton.Cryptography.Pgp;

public readonly ref struct DecryptionSecrets
{
    private readonly PgpPrivateKeyRing _privateKeyRing;
    private readonly PgpSessionKey? _sessionKey;
    private readonly ReadOnlySpan<byte> _password;

    public DecryptionSecrets(PgpPrivateKeyRing privateKeyRing)
        : this(privateKeyRing, null, [])
    {
    }

    public DecryptionSecrets(PgpSessionKey sessionKey)
        : this(default, sessionKey, [])
    {
    }

    public DecryptionSecrets(PgpPrivateKeyRing privateKeyRing, PgpSessionKey sessionKey)
        : this(privateKeyRing, sessionKey, [])
    {
    }

    public DecryptionSecrets(ReadOnlySpan<byte> password)
        : this(default, null, password)
    {
    }

    public DecryptionSecrets(PgpPrivateKeyRing privateKeyRing, ReadOnlySpan<byte> password)
        : this(privateKeyRing, null, password)
    {
    }

    private DecryptionSecrets(PgpPrivateKeyRing privateKeyRing, PgpSessionKey? sessionKey, ReadOnlySpan<byte> password)
    {
        _privateKeyRing = privateKeyRing;
        _sessionKey = sessionKey;
        _password = password;
    }

    public static implicit operator DecryptionSecrets(PgpPrivateKey privateKey)
    {
        var privateKeyRing = new PgpPrivateKeyRing(privateKey);
        return new DecryptionSecrets(privateKeyRing);
    }

    public static implicit operator DecryptionSecrets(PgpPrivateKeyRing privateKeyRing)
        => new(privateKeyRing);

    public static implicit operator DecryptionSecrets(PgpSessionKey sessionKey)
        => new(sessionKey);

    public static implicit operator DecryptionSecrets(ReadOnlySpan<byte> password)
        => new(password);

    [UnscopedRef]
    internal void Deconstruct(out PgpPrivateKeyRing keyRing, out PgpSessionKey? sessionKey, out ReadOnlySpan<byte> password)
    {
        keyRing = _privateKeyRing;
        sessionKey = _sessionKey;
        password = _password;
    }
}
