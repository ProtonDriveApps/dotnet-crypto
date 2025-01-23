using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpPrivateKeyRing : IDecryptionKeyRingSource, IVerificationKeyRingSource, IEncryptionKeyRingSource, ISigningKeyRingSource
{
    public PgpPrivateKeyRing(IReadOnlyList<PgpPrivateKey> keys)
    {
        if (keys.Count == 1)
        {
            SingleGoKey = keys[0].GoKey;
            return;
        }

        var multipleGoKeys = new GoKey[keys.Count];
        multipleGoKeys.AsSpan().FillWithTransform(keys, key => key.GoKey);
        MultipleGoKeys = multipleGoKeys;
    }

    public PgpPrivateKeyRing(PgpPrivateKey key)
    {
        SingleGoKey = key.GoKey;
    }

    PgpPrivateKeyRing IDecryptionKeyRingSource.DecryptionKeyRing => this;
    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;
    PgpPrivateKeyRing ISigningKeyRingSource.SigningKeyRing => this;

    public int Count => SingleGoKey is not null ? 1 : MultipleGoKeys?.Length ?? 0;

    private GoKey? SingleGoKey { get; }
    private GoKey[]? MultipleGoKeys { get; }

    public static implicit operator PgpPrivateKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPrivateKeyRing keyRing) => new(keyRing.SingleGoKey, keyRing.MultipleGoKeys);

    /// <summary>
    /// Gets the native Go handles for the keys.
    /// </summary>
    /// <remarks>
    /// Only call this just before calling a native function.
    /// </remarks>
    internal ReadOnlySpan<nint> DangerousGetGoKeyHandles()
    {
        if (SingleGoKey is not null)
        {
            return MemoryMarshal.CreateReadOnlySpan(ref SingleGoKey.DangerousGetHandleRef(), 1);
        }

        if (MultipleGoKeys is null)
        {
            return [];
        }

        var goKeyHandles = new nint[MultipleGoKeys.Length];
        goKeyHandles.AsSpan().FillWithTransform(MultipleGoKeys, key => key.DangerousGetHandle());
        return goKeyHandles;
    }
}
