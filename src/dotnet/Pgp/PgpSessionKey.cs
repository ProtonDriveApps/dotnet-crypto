using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpSessionKey : IDisposable, IDecryptionSecretsSource, IEncryptionSecretsSource
{
    private readonly GoSessionKey? _goSessionKey;

    internal PgpSessionKey(GoSessionKey goSessionKey)
    {
        _goSessionKey = goSessionKey;
    }

    DecryptionSecrets IDecryptionSecretsSource.DecryptionSecrets => this;
    EncryptionSecrets IEncryptionSecretsSource.EncryptionSecrets => this;

    internal GoSessionKey GoSessionKey => _goSessionKey ?? throw new InvalidOperationException("Invalid handle");

    public static PgpSessionKey Generate(SymmetricCipher cipher = SymmetricCipher.Aes256)
    {
        using var goError = GoGenerate(cipher, out var unsafeHandle);
        goError.ThrowIfFailure();

        return new PgpSessionKey(new GoSessionKey(unsafeHandle));
    }

    public static PgpSessionKey Import(ReadOnlySpan<byte> token, SymmetricCipher cipher)
    {
        var handle = GoImport(MemoryMarshal.GetReference(token), (nuint)token.Length, cipher);

        return new PgpSessionKey(handle);
    }

    public (byte[] Token, SymmetricCipher Cipher) Export()
    {
        return GoSessionKey.Export();
    }

    public void ToKeyPackets(PgpKeyRing encryptionKeyRing, Stream outputStream, TimeProvider? timeProviderOverride = null)
    {
        GoSessionKey.ToKeyPackets(outputStream, encryptionKeyRing, timeProviderOverride);
    }

    public void Dispose()
    {
        GoSessionKey.Dispose();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_new_session_key_from_token")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoSessionKey GoImport(in byte token, nuint tokenLength, SymmetricCipher cipher);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_generate_session_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoGenerate(SymmetricCipher cipher, out nint sessionKeyHandle);
}
