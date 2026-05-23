using System.Buffers;
using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp;

public readonly partial struct PgpMessage : IDisposable
{
    private readonly MemoryHandle? _messageMemoryHandle;

    private PgpMessage(nint foreignHandle, MemoryHandle messageMemoryHandle)
    {
        ForeignHandle = new ForeignMessageSafeHandle(foreignHandle);
        _messageMemoryHandle = messageMemoryHandle;
    }

    private ForeignMessageSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static unsafe PgpMessage Open(ReadOnlyMemory<byte> message, PgpEncoding encoding = default)
    {
        var messageMemoryHandle = message.Pin();

        try
        {
            var messageHandle = ForeignFunctions.Create((byte*)messageMemoryHandle.Pointer, (nuint)message.Length, encoding == PgpEncoding.AsciiArmor);

            return new PgpMessage(messageHandle, messageMemoryHandle);
        }
        catch
        {
            messageMemoryHandle.Dispose();
            throw;
        }
    }

    public unsafe long[] GetEncryptionKeyIds()
    {
        ForeignFunctions.GetEncryptionKeyIds(ForeignHandle, out var keyIdsPointer, out var keyIdsLength);

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get encryption key IDs");
        }

        return InteropMemory.CopyToArrayAndFree<long>(keyIdsPointer, keyIdsLength);
    }

    public unsafe long[] GetSigningKeyIds()
    {
        ForeignFunctions.GetSigningKeyIds(ForeignHandle, out var keyIdsPointer, out var keyIdsLength);

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get signing key IDs");
        }

        return InteropMemory.CopyToArrayAndFree<long>(keyIdsPointer, keyIdsLength);
    }

    public int GetKeyPacketsLength()
    {
        return (int)ForeignFunctions.KeyPacketSplit(ForeignHandle);
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
        _messageMemoryHandle?.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_new")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial nint Create(byte* message, nuint messageLength, [MarshalAs(UnmanagedType.U1)] bool isArmored);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_get_enc_key_ids")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial void GetEncryptionKeyIds(ForeignMessageSafeHandle messageHandle, out long* keyIds, out nuint keyIdsLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_get_sig_key_ids")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial void GetSigningKeyIds(ForeignMessageSafeHandle messageHandle, out long* keyIds, out nuint keyIdsLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_key_packet_split")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial nuint KeyPacketSplit(ForeignMessageSafeHandle messageHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignMessageSafeHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        public ForeignMessageSafeHandle(nint handle)
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
