using System.Buffers;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

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
            var error = ForeignFunctions.Create(
                (byte*)messageMemoryHandle.Pointer,
                (nuint)message.Length,
                encoding == PgpEncoding.AsciiArmor,
                out var messageHandle);

            error.ThrowPgpExceptionIfAny();

            return new PgpMessage(messageHandle, messageMemoryHandle);
        }
        catch
        {
            messageMemoryHandle.Dispose();
            throw;
        }
    }

    public unsafe ulong[] GetEncryptionKeyIds()
    {
        ForeignFunctions.GetEncryptionKeyIds(ForeignHandle, out var keyIdsPointer, out var keyIdsLength).ThrowPgpExceptionIfAny();

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get encryption key IDs");
        }

        return InteropMemory.CopyToArrayAndFree<ulong>(keyIdsPointer, keyIdsLength);
    }

    public unsafe ulong[] GetSigningKeyIds()
    {
        ForeignFunctions.GetSigningKeyIds(ForeignHandle, out var keyIdsPointer, out var keyIdsLength).ThrowPgpExceptionIfAny();

        if (keyIdsPointer == null)
        {
            throw new CryptographicException("Failed to get signing key IDs");
        }

        return InteropMemory.CopyToArrayAndFree<ulong>(keyIdsPointer, keyIdsLength);
    }

    public int GetKeyPacketsLength()
    {
        var error = ForeignFunctions.KeyPacketSplit(ForeignHandle, out var keyPacketsLength);
        error.ThrowPgpExceptionIfAny();

        return (int)keyPacketsLength;
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
        public static unsafe partial InteropError Create(
            byte* message,
            nuint messageLength,
            [MarshalAs(UnmanagedType.U1)] bool isArmored,
            out nint messageHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_get_enc_key_ids")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError GetEncryptionKeyIds(ForeignMessageSafeHandle messageHandle, out ulong* keyIds, out nuint keyIdsLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_get_sig_key_ids")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError GetSigningKeyIds(ForeignMessageSafeHandle messageHandle, out ulong* keyIds, out nuint keyIdsLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_key_packet_split")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError KeyPacketSplit(ForeignMessageSafeHandle messageHandle, out nuint keyPacketsLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_message_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignMessageSafeHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
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
