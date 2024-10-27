using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpPublicKey : IVerificationKeyRingSource, IEncryptionKeyRingSource, IDisposable
{
    private readonly GoKey? _goKey;

    internal PgpPublicKey(GoKey goKey)
    {
        _goKey = goKey;
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    public int Version => GoKey.Version;
    public nint Id => GoKey.Id;
    public bool CanEncrypt => GoKey.CanEncrypt;
    public bool CanVerify => GoKey.CanVerify;
    public bool IsExpired => GoKey.IsExpired;
    public bool IsRevoked => GoKey.IsRevoked;

    internal GoKey GoKey => _goKey ?? throw new InvalidOperationException("Invalid handle");

    public static PgpPublicKey Import(ReadOnlySpan<byte> key, PgpEncoding? encoding = null)
    {
        using var goError = GoImport(MemoryMarshal.GetReference(key), (nuint)key.Length, encoding.ToGoEncoding(), out var unsafeHandle);
        goError.ThrowIfFailure();

        return new PgpPublicKey(new GoKey(unsafeHandle));
    }

    public void Export(Stream stream, PgpEncoding encoding)
    {
        GoKey.Export(stream, encoding);
    }

    public byte[] GetFingerprint() => GoKey.GetFingerprint();
    public string[] GetSha256Fingerprints() => GoKey.GetSha256Fingerprints();

    public override string ToString()
    {
        return GoKey.ToString();
    }

    public void Dispose()
    {
        GoKey.Dispose();
    }

    internal static PgpPublicKey FromUnsafeHandle(nint unsafeHandle)
    {
        return new PgpPublicKey(new GoKey(unsafeHandle));
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_public_key_import")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoImport(in byte key, nuint keyLength, GoPgpEncoding encoding, out nint publicKeyHandle);
}
