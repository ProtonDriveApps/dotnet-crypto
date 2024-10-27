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

        var goKeyHandles = new nint[keys.Count];
        goKeyHandles.AsSpan().FillWithTransform(keys, key => key.GoKey.DangerousGetHandle());
        MultipleKeyHandles = goKeyHandles;
    }

    public PgpPrivateKeyRing(PgpPrivateKey key)
    {
        SingleGoKey = key.GoKey;
    }

    PgpPrivateKeyRing IDecryptionKeyRingSource.DecryptionKeyRing => this;
    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;
    PgpPrivateKeyRing ISigningKeyRingSource.SigningKeyRing => this;

    public int Count => SingleGoKey is not null ? 1 : MultipleKeyHandles?.Length ?? 0;

    internal ReadOnlySpan<nint> GoKeyHandles => SingleGoKey is not null
        ? MemoryMarshal.CreateReadOnlySpan(ref SingleGoKey.DangerousGetHandleRef(), 1)
        : MultipleKeyHandles;

    private GoKey? SingleGoKey { get; }
    private IntPtr[]? MultipleKeyHandles { get; }

    public static implicit operator PgpPrivateKeyRing(PgpPrivateKey privateKey) => new(privateKey);
    public static implicit operator PgpKeyRing(PgpPrivateKeyRing keyRing) => new(keyRing.SingleGoKey, keyRing.MultipleKeyHandles);
    public static implicit operator ReadOnlySpan<nint>(PgpPrivateKeyRing keyRing) => keyRing.GoKeyHandles;
}
