using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents an unlocked OpenPGP private key, which can be used for all cryptographic operations.
/// </summary>
/// <remarks>
/// To immediately clear sensitive data, call the <see cref="Dispose()"/> method.
/// </remarks>
public readonly partial struct PgpPrivateKey
    : IDecryptionKeyRingSource, IVerificationKeyRingSource, IEncryptionKeyRingSource, ISigningKeyRingSource, IDisposable
{
    internal PgpPrivateKey(nint foreignHandle)
    {
        Base = new PgpKey(foreignHandle);
    }

    internal PgpPrivateKey(PgpKey baseKey)
    {
        Base = baseKey;
    }

    PgpPrivateKeyRing IDecryptionKeyRingSource.DecryptionKeyRing => this;
    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;
    PgpPrivateKeyRing ISigningKeyRingSource.SigningKeyRing => this;

    internal PgpKey Base { get; }

    public static implicit operator PgpKey(PgpPrivateKey privateKey) => privateKey.Base;

    public static unsafe PgpPrivateKey Generate(
        string name,
        string emailAddress,
        KeyGenerationAlgorithm algorithm,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var nameUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(name.Length);
        var nameUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(nameUtf8BytesMaxLength, out var nameHeapMemory, out var nameHeapMemoryOwner)
            ? nameHeapMemory.Span
            : stackalloc byte[nameUtf8BytesMaxLength];

        using (nameHeapMemoryOwner)
        {
            var emailAddressUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(emailAddress.Length);
            var emailAddressUtf8Bytes =
                MemoryProvider.GetHeapMemoryIfTooLargeForStack(
                    emailAddressUtf8BytesMaxLength,
                    out var emailAddressHeapMemory,
                    out var emailAddressHeapMemoryOwner)
                    ? emailAddressHeapMemory.Span
                    : stackalloc byte[emailAddressUtf8BytesMaxLength];

            using (emailAddressHeapMemoryOwner)
            {
                var nameUtf8BytesLength = Encoding.UTF8.GetBytes(name, nameUtf8Bytes);
                var emailAddressUtf8BytesLength = Encoding.UTF8.GetBytes(emailAddress, emailAddressUtf8Bytes);

                fixed (byte* nameUtf8BytesPointer = nameUtf8Bytes)
                {
                    fixed (byte* emailAddressUtf8BytesPointer = emailAddressUtf8Bytes)
                    {
                        var parameters = new InteropKeyGenerationParameters(
                            nameUtf8BytesPointer,
                            (nuint)nameUtf8BytesLength,
                            emailAddressUtf8BytesPointer,
                            (nuint)emailAddressUtf8BytesLength,
                            algorithm,
                            profile,
                            timeProviderOverride);

                        using var error = ForeignFunctions.Generate(parameters, out var privateKeyHandle);
                        error.ThrowPgpExceptionIfAny();

                        return new PgpPrivateKey(privateKeyHandle);
                    }
                }
            }
        }
    }

    public static PgpPrivateKey Import(ReadOnlySpan<byte> unlockedKeyBytes, PgpEncoding? encoding = null)
    {
        using var error = ForeignFunctions.Import(
            MemoryMarshal.GetReference(unlockedKeyBytes),
            (nuint)unlockedKeyBytes.Length,
            encoding.ToInteropEncoding(),
            out var keyHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpPrivateKey(keyHandle);
    }

    public static PgpPrivateKey ImportAndUnlock(ReadOnlySpan<byte> lockedKeyBytes, ReadOnlySpan<byte> passphrase, PgpEncoding? encoding = null)
    {
        using var error = ForeignFunctions.ImportUnlock(
            MemoryMarshal.GetReference(lockedKeyBytes),
            (nuint)lockedKeyBytes.Length,
            MemoryMarshal.GetReference(passphrase),
            (nuint)passphrase.Length,
            encoding.ToInteropEncoding(),
            out var privateKeyHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpPrivateKey(privateKeyHandle);
    }

    public void Export(Stream stream, PgpEncoding encoding) => Base.Export(stream, encoding);

    public int Export(Span<byte> outputBuffer, PgpEncoding encoding) => Base.Export(outputBuffer, encoding);

    public PgpSecretKey Lock(ReadOnlySpan<byte> passphrase)
    {
        using var error = ForeignFunctions.Lock(
            Base.ForeignHandle,
            MemoryMarshal.GetReference(passphrase),
            (nuint)passphrase.Length,
            out var lockedPrivateKeyHandle);

        error.ThrowPgpExceptionIfAny();

        return new PgpSecretKey(lockedPrivateKeyHandle);
    }

    public PgpPublicKey ToPublic()
    {
        using var error = ForeignFunctions.GetPublicKey(Base.ForeignHandle, out var publicKey);
        error.ThrowPgpExceptionIfAny();

        return new PgpPublicKey(publicKey);
    }

    public override string ToString() => Base.ToString();

    public void Dispose()
    {
        Base.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe ref struct InteropKeyGenerationParameters
    {
        public byte Profile;
        public bool HasGenerationTime;
        public bool HasUserId;
        public byte* Name;
        public nuint NameLength;
        public byte* EmailAddress;
        public nuint EmailAddressLength;
        public ulong GenerationTime;
        public byte Algorithm;

        public InteropKeyGenerationParameters(
            byte* name,
            nuint nameLength,
            byte* emailAddress,
            nuint emailAddressLength,
            KeyGenerationAlgorithm algorithm,
            PgpProfile profile,
            TimeProvider? timeProviderOverride)
        {
            Profile = (byte)profile;
            HasUserId = true;
            Name = name;
            NameLength = nameLength;
            EmailAddress = emailAddress;
            EmailAddressLength = emailAddressLength;
            Algorithm = (byte)algorithm;

            var timeProvider = timeProviderOverride ?? PgpEnvironment.DefaultTimeProviderOverride;

            if (timeProvider is not null)
            {
                HasGenerationTime = true;
                GenerationTime = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            }
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_generate_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Generate(in InteropKeyGenerationParameters parameters, out nint privateKeyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_private_key_import")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Import(
            in byte key,
            nuint keyLength,
            InteropPgpEncoding encoding,
            out nint importedKeyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_private_key_import_unlock")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError ImportUnlock(
            in byte key,
            nuint keyLength,
            in byte passphrase,
            nuint passphraseLength,
            InteropPgpEncoding encoding,
            out nint importedKeyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_lock")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Lock(ForeignKeySafeHandle unlockedKeyHandle, in byte passphrase, nuint passphraseLength, out nint lockedKeyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_private_key_get_public_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError GetPublicKey(ForeignKeySafeHandle privateKeyHandle, out nint publicKeyHandle);
    }
}
