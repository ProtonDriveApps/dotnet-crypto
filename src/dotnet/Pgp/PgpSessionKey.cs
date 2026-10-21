using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpSessionKey : IDisposable, IDecryptionSecretsSource, IEncryptionSecretsSource, IForeignHandleProxy
{
    internal PgpSessionKey(nint foreignHandle)
        : this(new ForeignSessionKeySafeHandle(foreignHandle))
    {
    }

    private PgpSessionKey(ForeignSessionKeySafeHandle foreignHandle)
    {
        ForeignHandle = foreignHandle;
    }

    DecryptionSecrets IDecryptionSecretsSource.DecryptionSecrets => this;
    EncryptionSecrets IEncryptionSecretsSource.EncryptionSecrets => this;

    SafeHandle IForeignHandleProxy.ForeignHandle => ForeignHandle;

    private ForeignSessionKeySafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static PgpSessionKey Generate(SymmetricCipher cipher = SymmetricCipher.Aes256)
    {
        using var error = ForeignFunctions.Generate(cipher, out var sessionKeyHandle);
        error.ThrowPgpOrStreamExceptionIfAny();

        return new PgpSessionKey(sessionKeyHandle);
    }

    public static PgpSessionKey GenerateForAead(SymmetricCipher cipher = SymmetricCipher.Aes256)
    {
        using var error = ForeignFunctions.GenerateForAead(cipher, out var sessionKeyHandle);
        error.ThrowPgpOrStreamExceptionIfAny();

        return new PgpSessionKey(sessionKeyHandle);
    }

    public static PgpSessionKey Import(ReadOnlySpan<byte> token, SymmetricCipher cipher)
    {
        using var error = ForeignFunctions.Import(MemoryMarshal.GetReference(token), (nuint)token.Length, cipher, out var sessionKeyHandle);
        error.ThrowPgpExceptionIfAny();

        return new PgpSessionKey(sessionKeyHandle);
    }

    public static PgpSessionKey ImportForAead(ReadOnlySpan<byte> token, SymmetricCipher cipher)
    {
        using var error = ForeignFunctions.ImportForAead(MemoryMarshal.GetReference(token), (nuint)token.Length, cipher, out var sessionKeyHandle);
        error.ThrowPgpExceptionIfAny();

        return new PgpSessionKey(sessionKeyHandle);
    }

    public unsafe byte[] Export()
    {
        using var error = ForeignFunctions.Export(ForeignHandle, out var tokenPointer, out var tokenLength);
        error.ThrowPgpExceptionIfAny();

        if (tokenPointer == null)
        {
            throw new CryptographicException("Failed to export session key");
        }

        return InteropMemory.CopyToArrayAndFree<byte>(tokenPointer, tokenLength);
    }

    public bool TryGetCipher([NotNullWhen(true)] out SymmetricCipher? cipher)
    {
        using var error = ForeignFunctions.GetCipher(ForeignHandle, out var foreignCipher);

        // For PKESKv6, the algorithm is not always set
        if (error.Any && IsAead())
        {
            cipher = null;
            return false;
        }

        error.ThrowPgpOrStreamExceptionIfAny();

        cipher = (SymmetricCipher)foreignCipher;
        return true;
    }

    public unsafe void ToKeyPackets(PgpKeyRing encryptionKeyRing, Stream outputStream, PgpProfile profile = default, TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* encryptionKeysPointer = encryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropEncryptionParameters(
                profile,
                encryptionKeysPointer,
                (nuint)encryptionKeyRing.Count,
                null,
                0,
                null,
                null,
                0,
                false,
                false,
                false,
                0,
                null,
                timeProviderOverride);

            var outputStreamHandle = GCHandle.Alloc(outputStream);
            try
            {
                var outputWriter = InteropWriter.FromStreamHandle(outputStreamHandle);

                using var error = ForeignFunctions.Encrypt(parameters, ForeignHandle, outputWriter);
                error.ThrowPgpOrStreamExceptionIfAny();
            }
            finally
            {
                outputStreamHandle.Free();
            }
        }
    }

    public bool IsAead()
    {
        return ForeignFunctions.IsAead(ForeignHandle, out var isAead).SucceededOrThrowPgpException() && isAead;
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_generate_session_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Generate(SymmetricCipher cipher, out nint keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_generate_session_key_aead")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError GenerateForAead(SymmetricCipher cipher, out nint keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_new_session_key_from_token")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Import(in byte token, nuint tokenLength, SymmetricCipher cipher, out ForeignSessionKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_new_session_key_from_token_aead")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError ImportForAead(in byte token, nuint tokenLength, SymmetricCipher cipher, out ForeignSessionKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_session_key_export_token")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Export(ForeignSessionKeySafeHandle keyHandle, out byte* tokenPointer, out nuint tokenLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_session_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Encrypt(
            in InteropEncryptionParameters parameters,
            ForeignSessionKeySafeHandle keyHandle,
            InteropWriter outputWriter);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_session_key_get_algorithm")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError GetCipher(ForeignSessionKeySafeHandle keyHandle, out byte cipher);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_session_key_is_aead")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError IsAead(ForeignSessionKeySafeHandle keyHandle, [MarshalAs(UnmanagedType.I1)] out bool isAead);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_session_key_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignSessionKeySafeHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
    {
        public ForeignSessionKeySafeHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            ForeignFunctions.ReleaseHandle(handle);

            return true;
        }
    }
}
