using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpKeyRing : IVerificationKeyRingSource, IEncryptionKeyRingSource
{
    private readonly ForeignKeySafeHandle? _singleKeyHandle;
    private readonly ForeignKeySafeHandle[]? _multipleKeyHandles;

    public PgpKeyRing(IReadOnlyList<PgpKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleKeyHandle = keys[0].ForeignHandle;
            return;
        }

        var keyHandles = new ForeignKeySafeHandle[keys.Count];
        keyHandles.AsSpan().FillWithTransform(keys, key => key.ForeignHandle);
        _multipleKeyHandles = keyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPrivateKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleKeyHandle = keys[0].Base.ForeignHandle;
            return;
        }

        var keyHandles = new ForeignKeySafeHandle[keys.Count];
        keyHandles.AsSpan().FillWithTransform(keys, key => key.Base.ForeignHandle);
        _multipleKeyHandles = keyHandles;
    }

    public PgpKeyRing(IReadOnlyList<PgpPublicKey> keys)
    {
        if (keys.Count == 1)
        {
            _singleKeyHandle = keys[0].Base.ForeignHandle;
            return;
        }

        var keyHandles = new ForeignKeySafeHandle[keys.Count];
        keyHandles.AsSpan().FillWithTransform(keys, key => key.Base.ForeignHandle);
        _multipleKeyHandles = keyHandles;
    }

    public PgpKeyRing(PgpKey key)
    {
        _singleKeyHandle = key.ForeignHandle;
    }

    public PgpKeyRing(PgpPrivateKey key)
    {
        _singleKeyHandle = key.Base.ForeignHandle;
    }

    public PgpKeyRing(PgpPublicKey key)
    {
        _singleKeyHandle = key.Base.ForeignHandle;
    }

    internal PgpKeyRing(ForeignKeySafeHandle? singleKeyHandle, ForeignKeySafeHandle[]? multipleKeyHandles)
    {
        _singleKeyHandle = singleKeyHandle;
        _multipleKeyHandles = multipleKeyHandles;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    public int Count => _singleKeyHandle is not null ? 1 : _multipleKeyHandles?.Length ?? 0;

    public static implicit operator PgpKeyRing(PgpKey key) => new(key);
    public static implicit operator PgpKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPublicKey publicKey) => new(publicKey);

    /// <summary>
    /// Gets the foreign handles for the keys.
    /// </summary>
    /// <remarks>
    /// Only call this just before calling a foreign function.
    /// </remarks>
    internal ReadOnlySpan<nint> DangerousGetForeignKeyHandles()
    {
        if (_singleKeyHandle is not null)
        {
            return MemoryMarshal.CreateReadOnlySpan(ref _singleKeyHandle.DangerousGetHandleRef(), 1);
        }

        if (_multipleKeyHandles is null)
        {
            return [];
        }

        var keyHandles = new nint[_multipleKeyHandles.Length];
        keyHandles.AsSpan().FillWithTransform(_multipleKeyHandles, key => key.DangerousGetHandle());
        return keyHandles;
    }
}
