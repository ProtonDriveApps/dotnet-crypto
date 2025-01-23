using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpKeyRing : IVerificationKeyRingSource, IEncryptionKeyRingSource
{
    private readonly GoKey? _singleGoKey;
    private readonly GoKey[]? _multipleGoKeys;

    public PgpKeyRing(IReadOnlyList<PgpKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new GoKey[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey);
        _multipleGoKeys = goKeyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPrivateKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new GoKey[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey);
        _multipleGoKeys = goKeyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPublicKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new GoKey[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey);
        _multipleGoKeys = goKeyHandles;
    }

    public PgpKeyRing(PgpKey key)
    {
        _singleGoKey = key.GoKey;
    }

    public PgpKeyRing(PgpPrivateKey key)
    {
        _singleGoKey = key.GoKey;
    }

    public PgpKeyRing(PgpPublicKey key)
    {
        _singleGoKey = key.GoKey;
    }

    internal PgpKeyRing(GoKey? singleGoKey, GoKey[]? multipleGoKeys)
    {
        _singleGoKey = singleGoKey;
        _multipleGoKeys = multipleGoKeys;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    public int Count => _singleGoKey is not null ? 1 : _multipleGoKeys?.Length ?? 0;

    public static implicit operator PgpKeyRing(PgpKey key) => new(key);
    public static implicit operator PgpKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPublicKey publicKey) => new(publicKey);

    /// <summary>
    /// Gets the native Go handles for the keys.
    /// </summary>
    /// <remarks>
    /// Only call this just before calling a native function.
    /// </remarks>
    internal ReadOnlySpan<nint> DangerousGetGoKeyHandles()
    {
        if (_singleGoKey is not null)
        {
            return MemoryMarshal.CreateReadOnlySpan(ref _singleGoKey.DangerousGetHandleRef(), 1);
        }

        if (_multipleGoKeys is null)
        {
            return [];
        }

        var goKeyHandles = new nint[_multipleGoKeys.Length];
        goKeyHandles.AsSpan().FillWithTransform(_multipleGoKeys, key => key.DangerousGetHandle());
        return goKeyHandles;
    }
}
