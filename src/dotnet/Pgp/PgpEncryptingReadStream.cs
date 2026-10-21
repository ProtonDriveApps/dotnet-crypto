using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpEncryptingReadStream : BaseReadOnlyStream
{
    private readonly ForeignAsyncReader _foreignReader;
    private readonly ExceptionRecordingStream _plainDataInputStream;
    private readonly ExceptionRecordingStream? _signatureRecordingStream;
    private readonly ExceptionRecordingStream? _keyPacketRecordingStream;

    // Not readonly because freeing the handle requires mutability, but should never be reassigned after construction
    private GCHandle _plainDataInputStreamHandle;
    private GCHandle _signatureOutputStreamHandle;
    private GCHandle _keyPacketsOutputStreamHandle;

    private PgpEncryptingReadStream(
        ForeignAsyncReader foreignReader,
        ExceptionRecordingStream plainDataInputStream,
        ExceptionRecordingStream? signatureRecordingStream,
        ExceptionRecordingStream? keyPacketRecordingStream,
        GCHandle plainDataInputStreamHandle,
        GCHandle signatureOutputStreamHandle,
        GCHandle keyPacketsOutputStreamHandle)
    {
        _foreignReader = foreignReader;
        _plainDataInputStream = plainDataInputStream;
        _signatureRecordingStream = signatureRecordingStream;
        _keyPacketRecordingStream = keyPacketRecordingStream;
        _plainDataInputStreamHandle = plainDataInputStreamHandle;
        _signatureOutputStreamHandle = signatureOutputStreamHandle;
        _keyPacketsOutputStreamHandle = keyPacketsOutputStreamHandle;
    }

    ~PgpEncryptingReadStream()
    {
        Dispose(false);
    }

    public static PgpEncryptingReadStream Open(
        Stream plainDataInputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Create(
            plainDataInputStream,
            null,
            null,
            encryptionSecrets,
            default,
            encoding,
            compression,
            default,
            profile,
            aeadStreamingChunkLength,
            null,
            timeProviderOverride);
    }

    public static PgpEncryptingReadStream Open(
        Stream plainDataInputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Create(
            plainDataInputStream,
            null,
            null,
            encryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            default,
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);
    }

    public static PgpEncryptingReadStream Open(
        Stream plainDataInputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Create(
            plainDataInputStream,
            null,
            signatureOutputStream,
            encryptionSecrets,
            signingKeyRing,
            encoding,
            messageCompression,
            signatureEncryptionState,
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);
    }

    public static PgpEncryptingReadStream OpenSplit(
        Stream plainDataInputStream,
        Stream keyPacketsOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Create(
            plainDataInputStream,
            keyPacketsOutputStream,
            null,
            encryptionSecrets,
            default,
            default,
            messageCompression,
            default,
            profile,
            aeadStreamingChunkLength,
            null,
            timeProviderOverride);
    }

    public static PgpEncryptingReadStream OpenSplit(
        Stream plainDataInputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Create(
            plainDataInputStream,
            keyPacketsOutputStream,
            signatureOutputStream,
            encryptionSecrets,
            signingKeyRing,
            default,
            messageCompression,
            signatureEncryptionState,
            profile,
            aeadStreamingChunkLength,
            signingContext,
            timeProviderOverride);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        return _foreignReader.Read(
            ref MemoryMarshal.GetReference(buffer),
            buffer.Length,
            _plainDataInputStream,
            _keyPacketRecordingStream,
            _signatureRecordingStream);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return _foreignReader.ReadAsync(
            buffer,
            cancellationToken,
            _plainDataInputStream,
            _keyPacketRecordingStream,
            _signatureRecordingStream);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _foreignReader.Dispose();
        }

        if (_plainDataInputStreamHandle.IsAllocated)
        {
            _plainDataInputStreamHandle.Free();
        }

        if (_signatureOutputStreamHandle.IsAllocated)
        {
            _signatureOutputStreamHandle.Free();
        }

        if (_keyPacketsOutputStreamHandle.IsAllocated)
        {
            _keyPacketsOutputStreamHandle.Free();
        }

        base.Dispose(disposing);
    }

    private static unsafe PgpEncryptingReadStream Create(
        Stream plainDataInputStream,
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
        var plainDataRecordingStream = new ExceptionRecordingStream(plainDataInputStream);
        var plainDataInputStreamHandle = GCHandle.Alloc(plainDataRecordingStream);

        ExceptionRecordingStream? signatureRecordingStream = null;
        ExceptionRecordingStream? keyPacketRecordingStream = null;
        var signatureOutputStreamHandle = default(GCHandle);
        var keyPacketOutputStreamHandle = default(GCHandle);
        ForeignAsyncReader? foreignReader = null;

        try
        {
            InteropWriter signatureWriter = default;
            InteropWriter keyPacketWriter = default;

            if (signatureOutputStream is not null)
            {
                signatureRecordingStream = new ExceptionRecordingStream(signatureOutputStream);
                signatureOutputStreamHandle = GCHandle.Alloc(signatureRecordingStream);
                signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);
            }

            if (keyPacketsOutputStream is not null)
            {
                keyPacketRecordingStream = new ExceptionRecordingStream(keyPacketsOutputStream);
                keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketRecordingStream);
                keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);
            }

            var (encryptionKeyRing, sessionKey, password) = encryptionSecrets;

            fixed (nint* encryptionKeysPointer = encryptionKeyRing.DangerousGetForeignKeyHandles())
            {
                fixed (byte* passwordPointer = password)
                {
                    fixed (nint* signingKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
                    {
                        var parameters = new InteropEncryptionParameters(
                            profile,
                            encryptionKeysPointer,
                            (nuint)encryptionKeyRing.Count,
                            signingKeysPointer,
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

                        var interopPlaintextReader = new InteropReader(plainDataInputStreamHandle);
                        var interopEncoding = encoding.ToInteropEncoding();

                        using var error = ForeignFunctions.OpenEncryptReader(
                            parameters,
                            interopPlaintextReader,
                            signatureWriter,
                            keyPacketWriter,
                            (byte)interopEncoding,
                            WorkDispatcher.Pointer,
                            out var readerHandle);

                        foreignReader = new ForeignAsyncReader(readerHandle);

                        error.ThrowPgpOrStreamExceptionIfAny(plainDataRecordingStream, keyPacketRecordingStream, signatureRecordingStream);

                        return new PgpEncryptingReadStream(
                            foreignReader,
                            plainDataRecordingStream,
                            signatureRecordingStream,
                            keyPacketRecordingStream,
                            plainDataInputStreamHandle,
                            signatureOutputStreamHandle,
                            keyPacketOutputStreamHandle);
                    }
                }
            }
        }
        catch
        {
            foreignReader?.Dispose();

            if (keyPacketOutputStreamHandle.IsAllocated)
            {
                keyPacketOutputStreamHandle.Free();
            }

            if (signatureOutputStreamHandle.IsAllocated)
            {
                signatureOutputStreamHandle.Free();
            }

            if (plainDataInputStreamHandle.IsAllocated)
            {
                plainDataInputStreamHandle.Free();
            }

            throw;
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_reader_open")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenEncryptReader(
            in InteropEncryptionParameters parameters,
            InteropReader inputReader,
            InteropWriter signatureWriter,
            InteropWriter keyPacketWriter,
            byte encoding,
            delegate* unmanaged[Cdecl]<WorkDispatcher.InteropWorkTask, byte> workDispatcher,
            out nint outputReaderHandle);
    }
}
