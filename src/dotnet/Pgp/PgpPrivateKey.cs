using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpPrivateKey
    : IDecryptionKeyRingSource, IVerificationKeyRingSource, IEncryptionKeyRingSource, ISigningKeyRingSource, IDisposable
{
    private readonly GoKey? _goKey;

    private PgpPrivateKey(GoKey goKey)
    {
        _goKey = goKey;
    }

    PgpPrivateKeyRing IDecryptionKeyRingSource.DecryptionKeyRing => this;
    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;
    PgpPrivateKeyRing ISigningKeyRingSource.SigningKeyRing => this;

    public int Version => GoKey.Version;
    public nint Id => GoKey.Id;
    public bool CanEncrypt => GoKey.CanEncrypt;
    public bool CanVerify => GoKey.CanVerify;
    public bool IsExpired => GoKey.IsExpired;
    public bool IsRevoked => GoKey.IsRevoked;

    internal GoKey GoKey => _goKey ?? throw new InvalidOperationException("Invalid handle");

    public static unsafe PgpPrivateKey Generate(string name, string emailAddress, KeyGenerationAlgorithm algorithm, TimeProvider? timeProviderOverride = null)
    {
        GoKey? goPrivateKey;

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
                        var parameters = new KeyGenerationParameters(
                            nameUtf8BytesPointer,
                            (nuint)nameUtf8BytesLength,
                            emailAddressUtf8BytesPointer,
                            (nuint)emailAddressUtf8BytesLength,
                            algorithm,
                            timeProviderOverride);

                        using var goError = GoGenerate(parameters, out var unsafePrivateKeyHandle);
                        goError.ThrowIfFailure();

                        goPrivateKey = new GoKey(unsafePrivateKeyHandle);
                    }
                }
            }
        }

        return new PgpPrivateKey(goPrivateKey);
    }

    public static PgpPrivateKey ImportAndUnlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> passphrase, PgpEncoding? encoding = null)
    {
        using var goError = GoImport(
            MemoryMarshal.GetReference(key),
            (nuint)key.Length,
            MemoryMarshal.GetReference(passphrase),
            (nuint)passphrase.Length,
            encoding.ToGoEncoding(),
            out var privateKeyHandle);

        goError.ThrowIfFailure();

        return new PgpPrivateKey(new GoKey(privateKeyHandle));
    }

    public static PgpPrivateKey Import(ReadOnlySpan<byte> key, PgpEncoding? encoding = null)
    {
        using var goError = GoImport(
            MemoryMarshal.GetReference(key),
            (nuint)key.Length,
            Unsafe.NullRef<byte>(),
            0,
            encoding.ToGoEncoding(),
            out var privateKeyHandle);

        goError.ThrowIfFailure();

        return new PgpPrivateKey(new GoKey(privateKeyHandle));
    }

    public void Export(Stream stream, PgpEncoding encoding)
    {
        GoKey.Export(stream, encoding);
    }

    public PgpPrivateKey Lock(ReadOnlySpan<byte> passphrase)
    {
        using var goError = GoLock(GoKey, MemoryMarshal.GetReference(passphrase), (nuint)passphrase.Length, out var unsafeLockedPrivateKeyHandle);
        goError.ThrowIfFailure();

        return new PgpPrivateKey(new GoKey(unsafeLockedPrivateKeyHandle));
    }

    public PgpPublicKey ToPublic()
    {
        using var goError = GoGetPublicKey(GoKey, out var publicKey);
        goError.ThrowIfFailure();

        return new PgpPublicKey(new GoKey(publicKey));
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

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_generate_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoGenerate(in KeyGenerationParameters parameters, out nint privateKeyHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_lock")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoLock(GoKey goPrivateKey, in byte passphrase, nuint passphraseLength, out nint lockedPrivateKeyHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_private_key_import")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoImport(
        in byte key,
        nuint keyLength,
        in byte passphrase,
        nuint passphraseLength,
        GoPgpEncoding encoding,
        out nint privateKeyHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_private_key_get_public_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoGetPublicKey(GoKey goPrivateKey, out nint publicKeyHandle);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe ref struct KeyGenerationParameters
    {
        public bool HasGenerationTime;
        public bool HasUserId;
        public byte* Name;
        public nuint NameLength;
        public byte* EmailAddress;
        public nuint EmailAddressLength;
        public long GenerationTime;
        public byte Algorithm;

        public KeyGenerationParameters(
            byte* name,
            nuint nameLength,
            byte* emailAddress,
            nuint emailAddressLength,
            KeyGenerationAlgorithm algorithm,
            TimeProvider? timeProviderOverride)
        {
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
                GenerationTime = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            }
        }
    }
}
