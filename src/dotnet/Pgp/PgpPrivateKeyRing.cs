using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpPrivateKeyRing : IDecryptionKeyRingSource, IVerificationKeyRingSource, IEncryptionKeyRingSource, ISigningKeyRingSource
{
    public PgpPrivateKeyRing(IReadOnlyList<PgpPrivateKey> keys)
    {
        if (keys.Count == 1)
        {
            SingleKeyHandle = keys[0].Base.ForeignHandle;
            return;
        }

        var keyHandles = new ForeignKeySafeHandle[keys.Count];
        keyHandles.AsSpan().FillWithTransform(keys, key => key.Base.ForeignHandle);
        MultipleKeyHandles = keyHandles;
    }

    public PgpPrivateKeyRing(PgpPrivateKey key)
    {
        SingleKeyHandle = key.Base.ForeignHandle;
    }

    PgpPrivateKeyRing IDecryptionKeyRingSource.DecryptionKeyRing => this;
    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;
    PgpPrivateKeyRing ISigningKeyRingSource.SigningKeyRing => this;

    public int Count => SingleKeyHandle is not null ? 1 : MultipleKeyHandles?.Length ?? 0;

    private ForeignKeySafeHandle? SingleKeyHandle { get; }
    private ForeignKeySafeHandle[]? MultipleKeyHandles { get; }

    public static implicit operator PgpPrivateKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPrivateKeyRing keyRing) => new(keyRing.SingleKeyHandle, keyRing.MultipleKeyHandles);

    /// <summary>
    /// Gets the foreign handles for the keys.
    /// </summary>
    /// <remarks>
    /// Only call this just before calling a foreign function.
    /// </remarks>
    internal ReadOnlySpan<nint> DangerousGetForeignKeyHandles()
    {
        if (SingleKeyHandle is not null)
        {
            return MemoryMarshal.CreateReadOnlySpan(ref SingleKeyHandle.DangerousGetHandleRef(), 1);
        }

        if (MultipleKeyHandles is null)
        {
            return [];
        }

        var keyHandles = new nint[MultipleKeyHandles.Length];
        keyHandles.AsSpan().FillWithTransform(MultipleKeyHandles, key => key.DangerousGetHandle());
        return keyHandles;
    }
}
