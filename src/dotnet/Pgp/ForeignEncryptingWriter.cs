using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

internal partial struct ForeignEncryptingWriter(
    ForeignWriter foreignWriter,
    GCHandle dataOutputStreamHandle,
    GCHandle? keyPacketOutputStreamHandle,
    GCHandle? signatureOutputStreamHandle) : IDisposable
{
    private readonly ForeignWriter _foreignWriter = foreignWriter;
    private readonly GCHandle? _keyPacketOutputStreamHandle = keyPacketOutputStreamHandle;
    private readonly GCHandle? _signatureOutputStreamHandle = signatureOutputStreamHandle;
    private GCHandle _dataOutputStreamHandle = dataOutputStreamHandle;

    public bool CanWrite => _dataOutputStreamHandle.IsAllocated;

    internal static unsafe ForeignEncryptingWriter Create(
        Stream messageOutputStream,
        GCHandle? keyPacketOutputStreamHandle,
        in InteropWriter keyPacketWriter,
        GCHandle? signatureOutputStreamHandle,
        in InteropWriter interopSignatureWriter,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding,
        PgpCompression dataCompression,
        EncryptionState signatureEncryptionState,
        PgpProfile profile,
        long? aeadStreamingChunkLength,
        TimeProvider? timeProviderOverride)
    {
        var (encryptionKeyRing, sessionKey, password) = encryptionSecrets;

        fixed (nint* foreignEncryptionKeysPointer = encryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* foreignSigningKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
                {
                    var parameters = new InteropEncryptionParameters(
                        profile,
                        foreignEncryptionKeysPointer,
                        (nuint)encryptionKeyRing.Count,
                        foreignSigningKeysPointer,
                        (nuint)signingKeyRing.Count,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        signatureOutputStreamHandle.HasValue,
                        signatureEncryptionState == EncryptionState.Encrypted,
                        dataCompression != PgpCompression.None,
                        aeadStreamingChunkLength,
                        timeProviderOverride);

                    var messageOutputStreamHandle = GCHandle.Alloc(messageOutputStream);
                    try
                    {
                        var interopWriter = InteropWriter.FromStreamHandle(messageOutputStreamHandle);
                        var interopEncoding = encoding.ToInteropEncoding();

                        using var error = Unsafe.IsNullRef(in keyPacketWriter)
                            ? ForeignFunctions.OpenStream(parameters, interopWriter, interopSignatureWriter, interopEncoding, out var inputWriterHandle)
                            : ForeignFunctions.OpenStream(parameters, interopWriter, interopSignatureWriter, keyPacketWriter, out inputWriterHandle);

                        error.ThrowPgpExceptionIfAny();

                        return new ForeignEncryptingWriter(
                            new ForeignWriter(inputWriterHandle),
                            messageOutputStreamHandle,
                            keyPacketOutputStreamHandle,
                            signatureOutputStreamHandle);
                    }
                    catch
                    {
                        messageOutputStreamHandle.Free();
                        throw;
                    }
                }
            }
        }
    }

    public readonly void Write(ReadOnlySpan<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            var numberOfBytesWritten = _foreignWriter.Write(buffer);

            buffer = buffer[numberOfBytesWritten..];
        }
    }

    public readonly void WriteEnd()
    {
        _foreignWriter.WriteEnd();
    }

    public void Dispose()
    {
        var isAlreadyDisposed = !_dataOutputStreamHandle.IsAllocated;
        if (isAlreadyDisposed)
        {
            return;
        }

        _foreignWriter.Dispose();
        _dataOutputStreamHandle.Free();
        _keyPacketOutputStreamHandle?.Free();
        _signatureOutputStreamHandle?.Free();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenStream(
            in InteropEncryptionParameters parameters,
            InteropWriter outputWriter,
            in InteropWriter signatureWriter,
            InteropPgpEncoding encoding,
            out nint inputWriterHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_stream_split")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenStream(
            in InteropEncryptionParameters parameters,
            InteropWriter outputWriter,
            in InteropWriter signatureWriter,
            InteropWriter keyPacketWriter,
            out nint inputWriterHandle);
    }
}
