using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents a locked OpenPGP private key, which must be unlocked before it can be used for any cryptographic operation.
/// </summary>
/// <remarks>
/// When this key is imported, there is no validation that the key is actually locked.
/// </remarks>
public readonly partial struct PgpSecretKey : IDisposable
{
    internal PgpSecretKey(GoKey goKey)
    {
        GoKey = goKey;
    }

    public int Version => GoKey.Version;
    public nint Id => GoKey.Id;

    internal GoKey GoKey => field ?? throw new InvalidOperationException("Invalid handle");

    public static PgpSecretKey Import(ReadOnlySpan<byte> key, PgpEncoding? encoding = null)
    {
        using var goError = GoImport(
            MemoryMarshal.GetReference(key),
            (nuint)key.Length,
            encoding.ToGoEncoding(),
            out var privateKeyHandle);

        goError.ThrowIfFailure();

        return new PgpSecretKey(new GoKey(privateKeyHandle));
    }

    public PgpPrivateKey Unlock(ReadOnlySpan<byte> passphrase)
    {
        using var goError = GoUnlock(GoKey, MemoryMarshal.GetReference(passphrase), (nuint)passphrase.Length, out var unsafeUnlockedPrivateKeyHandle);
        goError.ThrowIfFailure();

        return new PgpPrivateKey(new GoKey(unsafeUnlockedPrivateKeyHandle));
    }

    public override string ToString()
    {
        return GoKey.ToString();
    }

    public void Dispose()
    {
        GoKey.Dispose();
    }

    internal void Export(Stream stream, PgpEncoding encoding)
    {
        GoKey.Export(stream, encoding);
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_unlock")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoUnlock(GoKey goPrivateKey, in byte passphrase, nuint passphraseLength, out nint unlockedPrivateKeyHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_private_key_import")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoImport(
        in byte key,
        nuint keyLength,
        GoPgpEncoding encoding,
        out nint privateKeyHandle);
}
