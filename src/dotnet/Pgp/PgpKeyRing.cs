using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpKeyRing : IVerificationKeyRingSource, IEncryptionKeyRingSource
{
    private readonly GoKey? _singleGoKey;
    private readonly nint[]? _multipleKeyHandles;

    public PgpKeyRing(IReadOnlyList<PgpKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new nint[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey.DangerousGetHandle());
        _multipleKeyHandles = goKeyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPrivateKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new nint[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey.DangerousGetHandle());
        _multipleKeyHandles = goKeyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPublicKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleGoKey = keys[0].GoKey;
            return;
        }

        var goKeyHandles = new nint[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey.DangerousGetHandle());
        _multipleKeyHandles = goKeyHandles;
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

    internal PgpKeyRing(GoKey? singleGoKey, nint[]? multipleKeyHandles)
    {
        _singleGoKey = singleGoKey;
        _multipleKeyHandles = multipleKeyHandles;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    public int Count => _singleGoKey is not null ? 1 : _multipleKeyHandles?.Length ?? 0;

    internal ReadOnlySpan<nint> GoKeyHandles => _singleGoKey is not null
        ? MemoryMarshal.CreateReadOnlySpan(ref _singleGoKey.DangerousGetHandleRef(), 1)
        : _multipleKeyHandles;

    public static implicit operator PgpKeyRing(PgpKey key) => new(key);
    public static implicit operator PgpKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPublicKey publicKey) => new(publicKey);
    public static implicit operator ReadOnlySpan<nint>(PgpKeyRing keyRing) => keyRing.GoKeyHandles;
}
