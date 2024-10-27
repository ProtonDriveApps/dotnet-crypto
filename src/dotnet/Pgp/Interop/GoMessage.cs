using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoMessage() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    private GoMessage(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public static unsafe GoMessage Open(byte* message, nuint messageLength, bool isArmored)
    {
        var unsafeHandle = GoCreate(message, messageLength, isArmored);

        return new GoMessage(unsafeHandle);
    }

    public unsafe long[] GetEncryptionKeyIds()
    {
        GoGetEncryptionKeyIds(this, out var keyIdsPointer, out var keyIdsLength);

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get encryption key IDs");
        }

        return CMemory.ConvertToArray<long>(keyIdsPointer, keyIdsLength);
    }

    public unsafe long[] GetSigningKeyIds()
    {
        GoGetSigningKeyIds(this, out var keyIdsPointer, out var keyIdsLength);

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get signing key IDs");
        }

        return CMemory.ConvertToArray<long>(keyIdsPointer, keyIdsLength);
    }

    public nuint GetKeyPacketsLength()
    {
        return GoKeyPacketSplit(this);
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_new")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial nint GoCreate(byte* message, nuint messageLength, [MarshalAs(UnmanagedType.U1)] bool isArmored);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_get_enc_key_ids")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoGetEncryptionKeyIds(GoMessage goMessage, out long* keyIds, out nuint keyIdsLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_get_sig_key_ids")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoGetSigningKeyIds(GoMessage goMessage, out long* keyIds, out nuint keyIdsLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_key_packet_split")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial nuint GoKeyPacketSplit(GoMessage goMessage);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_message_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);
}
