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
    internal PgpSecretKey(nint foreignHandle)
    {
        Base = new PgpKey(foreignHandle);
    }

    public nint Id => Base.Id;
    public int Version => Base.Version;

    internal PgpKey Base { get; }

    public static PgpSecretKey Import(ReadOnlySpan<byte> lockedKeyBytes, PgpEncoding? encoding = null)
    {
        using var error = ForeignFunctions.Import(
            MemoryMarshal.GetReference(lockedKeyBytes),
            (nuint)lockedKeyBytes.Length,
            encoding.ToInteropEncoding(),
            out var keyHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpSecretKey(keyHandle);
    }

    public void Export(Stream stream, PgpEncoding encoding = PgpEncoding.None) => Base.Export(stream, encoding);

    public int Export(Span<byte> outputBuffer, PgpEncoding encoding) => Base.Export(outputBuffer, encoding);

    public PgpPrivateKey Unlock(ReadOnlySpan<byte> passphrase)
    {
        using var error = ForeignFunctions.Unlock(
            Base.ForeignHandle,
            MemoryMarshal.GetReference(passphrase),
            (nuint)passphrase.Length,
            out var unlockedKeyHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpPrivateKey(unlockedKeyHandle);
    }

    public override string ToString() => Base.ToString();

    public void Dispose()
    {
        Base.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_private_key_import")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Import(
            in byte key,
            nuint keyLength,
            InteropPgpEncoding encoding,
            out nint importedKeyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_unlock")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Unlock(
            ForeignKeySafeHandle lockedKeyHandle,
            in byte passphrase,
            nuint passphraseLength,
            out nint unlockedKeyHandle);
    }
}
