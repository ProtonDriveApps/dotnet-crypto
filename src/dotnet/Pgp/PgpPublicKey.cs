using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents an OpenPGP public key, which can be used for encryption and verification operations.
/// </summary>
public readonly partial struct PgpPublicKey : IVerificationKeyRingSource, IEncryptionKeyRingSource, IDisposable
{
    internal PgpPublicKey(nint foreignHandle)
    {
        Base = new PgpKey(foreignHandle);
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    internal PgpKey Base { get; }

    public static implicit operator PgpKey(PgpPublicKey publicKey) => publicKey.Base;

    public static PgpPublicKey Import(ReadOnlySpan<byte> key, PgpEncoding? encoding = null)
    {
        using var error = ForeignFunctions.Import(MemoryMarshal.GetReference(key), (nuint)key.Length, encoding.ToInteropEncoding(), out var publicKeyHandle);
        error.ThrowPgpExceptionIfAny();

        return new PgpPublicKey(publicKeyHandle);
    }

    public void Export(Stream stream, PgpEncoding encoding) => Base.Export(stream, encoding);

    public int Export(Span<byte> outputBuffer, PgpEncoding encoding) => Base.Export(outputBuffer, encoding);

    public override string ToString() => Base.ToString();

    public void Dispose() => Base.Dispose();

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_public_key_import")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Import(in byte key, nuint keyLength, InteropPgpEncoding encoding, out nint publicKeyHandle);
    }
}
