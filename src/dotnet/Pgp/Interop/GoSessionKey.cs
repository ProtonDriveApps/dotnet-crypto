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

    public unsafe (byte[] Token, SymmetricCipher Cipher) Export()
    {
        GoExport(this, out var tokenPointer, out var tokenLength);

        if (tokenPointer == null)
        {
            throw new CryptographicException("Failed to export session key");
        }

        var token = CMemory.ConvertToArray<byte>(tokenPointer, tokenLength);

        using var goError = GoGetCipher(this, out var cipher);
        goError.ThrowIfFailure();

        return (token, (SymmetricCipher)cipher);
    }

    public unsafe void ToKeyPackets(Stream outputStream, PgpKeyRing encryptionKeyRing, TimeProvider? timeProviderOverride = null)
    {
        fixed (nint* goEncryptionKeysPointer = encryptionKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new GoEncryptionParameters(
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
                timeProviderOverride);

            var streamHandle = GCHandle.Alloc(outputStream);
            try
            {
                var goWriter = new GoExternalWriter(streamHandle);

                using var goError = GoEncrypt(parameters, this, goWriter);
                goError.ThrowIfFailure();
            }
            finally
            {
                streamHandle.Free();
            }
        }
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

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_session_key_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint goKey);
}
