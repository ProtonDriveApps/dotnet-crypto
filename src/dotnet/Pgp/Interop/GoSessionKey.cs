using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoSessionKey() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    public GoSessionKey(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public unsafe byte[] Export()
    {
        GoExport(this, out var tokenPointer, out var tokenLength);

        if (tokenPointer == null)
        {
            throw new CryptographicException("Failed to export session key");
        }

        return CMemory.ConvertToArray<byte>(tokenPointer, tokenLength);
    }

    public bool TryGetCipher([NotNullWhen(true)] out SymmetricCipher? cipher)
    {
        using var goError = GoGetCipher(this, out var goCipher);

        // For PKESKv6, the algorithm is not always set
        if (!goError.IsSuccess && IsAead())
        {
            cipher = null;
            return false;
        }

        goError.ThrowIfFailure();

        cipher = (SymmetricCipher)goCipher;
        return true;
    }

    public unsafe void ToKeyPackets(Stream outputStream, PgpKeyRing encryptionKeyRing, PgpProfile profile = default, TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goEncryptionKeysPointer = encryptionKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new GoEncryptionParameters(
                profile,
                goEncryptionKeysPointer,
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
                timeProviderOverride);

            var streamHandle = GCHandle.Alloc(outputStream);
            try
            {
                var goWriter = GoExternalWriter.FromStreamHandle(streamHandle);

                using var goError = GoEncrypt(parameters, this, goWriter);
                goError.ThrowIfFailure();
            }
            finally
            {
                streamHandle.Free();
            }
        }
    }

    public bool IsAead()
    {
        GoIsAead(this, out var isAead);

        return isAead;
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_session_key_export_token")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoExport(GoSessionKey goSessionKey, out byte* tokenPointer, out nuint tokenLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt_session_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoEncrypt(in GoEncryptionParameters parameters, GoSessionKey goSessionKey, GoExternalWriter outputWriter);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_session_key_get_algorithm")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoGetCipher(GoSessionKey goSessionKey, out byte cipher);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_session_key_is_aead")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoIsAead(GoSessionKey goSessionKey, [MarshalAs(UnmanagedType.I1)] out bool isAead);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_session_key_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint goKey);
}
