using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

internal partial struct ForeignEncryptingWriter(
    ForeignWriter foreignWriter,
    GCHandle dataOutputStreamHandle,
    GCHandle keyPacketOutputStreamHandle,
    GCHandle signatureOutputStreamHandle,
    ExceptionRecordingStream messageRecordingStream,
    ExceptionRecordingStream? keyPacketRecordingStream,
    ExceptionRecordingStream? signatureRecordingStream) : IDisposable
{
    private readonly ForeignWriter _foreignWriter = foreignWriter;
    private readonly ExceptionRecordingStream _messageRecordingStream = messageRecordingStream;
    private readonly ExceptionRecordingStream? _keyPacketRecordingStream = keyPacketRecordingStream;
    private readonly ExceptionRecordingStream? _signatureRecordingStream = signatureRecordingStream;
    private GCHandle _dataOutputStreamHandle = dataOutputStreamHandle;
    private GCHandle _keyPacketOutputStreamHandle = keyPacketOutputStreamHandle;
    private GCHandle _signatureOutputStreamHandle = signatureOutputStreamHandle;

    public bool CanWrite => _dataOutputStreamHandle.IsAllocated;

    internal static unsafe ForeignEncryptingWriter Open(
        Stream messageOutputStream,
        Stream? keyPacketsOutputStream,
        Stream? signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding,
        PgpCompression dataCompression,
        EncryptionState signatureEncryptionState,
        PgpProfile profile,
        long? aeadStreamingChunkLength,
        PgpSigningContext? signingContext,
        TimeProvider? timeProviderOverride)
    {
        var messageOutputStreamHandle = default(GCHandle);
        var keyPacketOutputStreamHandle = default(GCHandle);
        var signatureOutputStreamHandle = default(GCHandle);
        ExceptionRecordingStream? messageRecordingStream = null;
        ExceptionRecordingStream? keyPacketRecordingStream = null;
        ExceptionRecordingStream? signatureRecordingStream = null;
        ForeignWriter? foreignWriter = null;

        try
        {
            messageRecordingStream = new ExceptionRecordingStream(messageOutputStream);
            messageOutputStreamHandle = GCHandle.Alloc(messageRecordingStream);

            InteropWriter keyPacketWriter = default;

            if (keyPacketsOutputStream is not null)
            {
                keyPacketRecordingStream = new ExceptionRecordingStream(keyPacketsOutputStream);
                keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketRecordingStream);
                keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);
            }

            InteropWriter signatureWriter = default;

            if (signatureOutputStream is not null)
            {
                signatureRecordingStream = new ExceptionRecordingStream(signatureOutputStream);
                signatureOutputStreamHandle = GCHandle.Alloc(signatureRecordingStream);
                signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);
            }

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
                            signatureOutputStream is not null,
                            signatureEncryptionState == EncryptionState.Encrypted,
                            dataCompression != PgpCompression.None,
                            aeadStreamingChunkLength,
                            signingContext,
                            timeProviderOverride);

                        var interopWriter = InteropWriter.FromStreamHandle(messageOutputStreamHandle);
                        var interopEncoding = encoding.ToInteropEncoding();

                        using var error = keyPacketOutputStreamHandle.IsAllocated
                            ? signatureOutputStreamHandle.IsAllocated
                                ? ForeignFunctions.OpenStream(parameters, interopWriter, signatureWriter, keyPacketWriter, out var inputWriterHandle)
                                : ForeignFunctions.OpenStream(parameters, interopWriter, Unsafe.NullRef<InteropWriter>(), keyPacketWriter, out inputWriterHandle)
                            : signatureOutputStreamHandle.IsAllocated
                                ? ForeignFunctions.OpenStream(parameters, interopWriter, signatureWriter, interopEncoding, out inputWriterHandle)
                                : ForeignFunctions.OpenStream(parameters, interopWriter, Unsafe.NullRef<InteropWriter>(), interopEncoding, out inputWriterHandle);

                        error.ThrowPgpOrStreamExceptionIfAny(messageRecordingStream, keyPacketRecordingStream, signatureRecordingStream);

                        foreignWriter = new ForeignWriter(inputWriterHandle);

                        return new ForeignEncryptingWriter(
                            foreignWriter.Value,
                            messageOutputStreamHandle,
                            keyPacketOutputStreamHandle,
                            signatureOutputStreamHandle,
                            messageRecordingStream,
                            keyPacketRecordingStream,
                            signatureRecordingStream);
                    }
                }
            }
        }
        catch
        {
            foreignWriter?.Dispose();
            if (messageOutputStreamHandle.IsAllocated)
            {
                messageOutputStreamHandle.Free();
            }

            if (keyPacketOutputStreamHandle.IsAllocated)
            {
                keyPacketOutputStreamHandle.Free();
            }

            if (signatureOutputStreamHandle.IsAllocated)
            {
                signatureOutputStreamHandle.Free();
            }

            throw;
        }
    }

    public readonly void Write(ReadOnlySpan<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            var numberOfBytesWritten = _foreignWriter.Write(
                buffer,
                _messageRecordingStream,
                _keyPacketRecordingStream,
                _signatureRecordingStream);

            buffer = buffer[numberOfBytesWritten..];
        }
    }

    public readonly void WriteEnd()
    {
        _foreignWriter.WriteEnd(
            _messageRecordingStream,
            _keyPacketRecordingStream,
            _signatureRecordingStream);
    }

    public void Dispose()
    {
        if (!_dataOutputStreamHandle.IsAllocated)
        {
            return;
        }

        _foreignWriter.Dispose();

        if (_dataOutputStreamHandle.IsAllocated)
        {
            _dataOutputStreamHandle.Free();
        }

        if (_keyPacketOutputStreamHandle.IsAllocated)
        {
            _keyPacketOutputStreamHandle.Free();
        }

        if (_signatureOutputStreamHandle.IsAllocated)
        {
            _signatureOutputStreamHandle.Free();
        }
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
