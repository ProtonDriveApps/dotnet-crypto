using System.Runtime.CompilerServices;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed class PgpEncryptingWriteStream : BaseWriteOnlyStream
{
    private ForeignEncryptingWriter _foreignWriter;

    private bool _endWritten;

    private PgpEncryptingWriteStream(ForeignEncryptingWriter foreignWriter)
    {
        _foreignWriter = foreignWriter;
    }

    ~PgpEncryptingWriteStream()
    {
        Dispose(false);
    }

    public static PgpEncryptingWriteStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var foreignStream = ForeignEncryptingWriter.Create(
            messageOutputStream,
            null,
            Unsafe.NullRef<InteropWriter>(),
            null,
            Unsafe.NullRef<InteropWriter>(),
            encryptionSecrets,
            default,
            encoding,
            compression,
            default,
            profile,
            aeadStreamingChunkLength,
            timeProviderOverride);

        return new PgpEncryptingWriteStream(foreignStream);
    }

    public static PgpEncryptingWriteStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var foreignStream = ForeignEncryptingWriter.Create(
            messageOutputStream,
            null,
            Unsafe.NullRef<InteropWriter>(),
            null,
            Unsafe.NullRef<InteropWriter>(),
            encryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            default,
            profile,
            aeadStreamingChunkLength,
            timeProviderOverride);

        return new PgpEncryptingWriteStream(foreignStream);
    }

    public static PgpEncryptingWriteStream Open(
        Stream messageOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
        try
        {
            var signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);

            var foreignStream = ForeignEncryptingWriter.Create(
                messageOutputStream,
                null,
                Unsafe.NullRef<InteropWriter>(),
                signatureOutputStreamHandle,
                signatureWriter,
                encryptionSecrets,
                signingKeyRing,
                encoding,
                messageCompression,
                signatureEncryptionState,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);

            return new PgpEncryptingWriteStream(foreignStream);
        }
        catch
        {
            signatureOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingWriteStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var foreignStream = ForeignEncryptingWriter.Create(
                messageOutputStream,
                keyPacketOutputStreamHandle,
                keyPacketWriter,
                null,
                Unsafe.NullRef<InteropWriter>(),
                encryptionSecrets,
                default,
                default,
                messageCompression,
                default,
                profile,
                aeadStreamingChunkLength,
                timeProviderOverride);

            return new PgpEncryptingWriteStream(foreignStream);
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingWriteStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
            try
            {
                var signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);

                var foreignStream = ForeignEncryptingWriter.Create(
                    messageOutputStream,
                    keyPacketOutputStreamHandle,
                    keyPacketWriter,
                    signatureOutputStreamHandle,
                    signatureWriter,
                    encryptionSecrets,
                    signingKeyRing,
                    default,
                    messageCompression,
                    signatureEncryptionState,
                    profile,
                    aeadStreamingChunkLength,
                    timeProviderOverride);

                return new PgpEncryptingWriteStream(foreignStream);
            }
            catch
            {
                signatureOutputStreamHandle.Free();
                throw;
            }
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
            throw;
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _foreignWriter.Write(buffer);
    }

    public override void Close()
    {
        try
        {
            if (_endWritten)
            {
                return;
            }

            _foreignWriter.WriteEnd();

            _endWritten = true;
        }
        finally
        {
            base.Close();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _foreignWriter.Dispose();
        }

        base.Dispose(disposing);
    }
}
