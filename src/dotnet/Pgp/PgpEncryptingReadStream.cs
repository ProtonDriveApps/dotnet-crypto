using System.Buffers;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed class PgpEncryptingReadStream : BaseReadOnlyStream
{
    private const int OverflowBufferLength = 8192;

    private readonly Stream _plainDataInputStream;
    private readonly InternalOutputStream _internalOutputStream;
    private readonly MemoryStream _overflowStream;
    private readonly PgpEncoding _encoding;

    private ForeignEncryptingWriter _foreignWriter;

    private byte[]? _readBuffer;
    private bool _endWritten;

    private PgpEncryptingReadStream(
        ForeignEncryptingWriter foreignWriter,
        Stream plainDataInputStream,
        InternalOutputStream internalOutputStream,
        MemoryStream overflowStream,
        PgpEncoding encoding)
    {
        _foreignWriter = foreignWriter;
        _plainDataInputStream = plainDataInputStream;
        _internalOutputStream = internalOutputStream;
        _overflowStream = overflowStream;
        _encoding = encoding;

        _overflowStream.Seek(0, SeekOrigin.Begin);
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
        var overflowStream = new MemoryStream(OverflowBufferLength);
        var internalOutputStream = new InternalOutputStream(overflowStream);

        var foreignStream = ForeignEncryptingWriter.Create(
            internalOutputStream,
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

        return new PgpEncryptingReadStream(foreignStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
    }

    public static PgpEncryptingReadStream Open(
        Stream plainDataInputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        long? aeadStreamingChunkLength = null,
        TimeProvider? timeProviderOverride = null)
    {
        var overflowStream = new MemoryStream(OverflowBufferLength);
        var internalOutputStream = new InternalOutputStream(overflowStream);

        var foreignStream = ForeignEncryptingWriter.Create(
            internalOutputStream,
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

        return new PgpEncryptingReadStream(foreignStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
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
        TimeProvider? timeProviderOverride = null)
    {
        var overflowStream = new MemoryStream(OverflowBufferLength);
        var internalOutputStream = new InternalOutputStream(overflowStream);

        var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
        try
        {
            var signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);

            var foreignStream = ForeignEncryptingWriter.Create(
                internalOutputStream,
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

            return new PgpEncryptingReadStream(foreignStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
        }
        catch
        {
            signatureOutputStreamHandle.Free();
            throw;
        }
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
        var overflowStream = new MemoryStream(OverflowBufferLength);
        var internalOutputStream = new InternalOutputStream(overflowStream);

        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var foreignStream = ForeignEncryptingWriter.Create(
                internalOutputStream,
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

            return new PgpEncryptingReadStream(foreignStream, plainDataInputStream, internalOutputStream, overflowStream, default);
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
            throw;
        }
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
        TimeProvider? timeProviderOverride = null)
    {
        var overflowStream = new MemoryStream(OverflowBufferLength);
        var internalOutputStream = new InternalOutputStream(overflowStream);

        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var keyPacketWriter = InteropWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
            try
            {
                var signatureWriter = InteropWriter.FromStreamHandle(signatureOutputStreamHandle);

                var foreignStream = ForeignEncryptingWriter.Create(
                    internalOutputStream,
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

                return new PgpEncryptingReadStream(foreignStream, plainDataInputStream, internalOutputStream, overflowStream, default);
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

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        var totalBytesProduced = 0;
        var inputEndReached = _endWritten;

        while (totalBytesProduced < buffer.Length)
        {
            totalBytesProduced += DrainAnyOverflow(buffer[totalBytesProduced..]);

            if (totalBytesProduced == buffer.Length || inputEndReached)
            {
                break;
            }

            var (inputBytesRead, bytesProduced) = ReadFromInput(buffer[totalBytesProduced..]);

            inputEndReached = inputBytesRead <= 0;
            totalBytesProduced += bytesProduced;
        }

        return totalBytesProduced;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var totalBytesProduced = 0;
        var inputEndReached = _endWritten;

        while (totalBytesProduced < buffer.Length)
        {
            totalBytesProduced += DrainAnyOverflow(buffer.Span[totalBytesProduced..]);

            if (totalBytesProduced == buffer.Length || inputEndReached)
            {
                break;
            }

            var (inputBytesRead, bytesProduced) = await ReadFromInputAsync(buffer[totalBytesProduced..], cancellationToken).ConfigureAwait(false);

            inputEndReached = inputBytesRead <= 0;
            totalBytesProduced += bytesProduced;
        }

        return totalBytesProduced;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_readBuffer is not null)
            {
                CryptographicOperations.ZeroMemory(_readBuffer);
                ArrayPool<byte>.Shared.Return(_readBuffer);
                _readBuffer = null;
            }

            _foreignWriter.Dispose();
        }

        base.Dispose(disposing);
    }

    private ReadFromInputResult ReadFromInput(Span<byte> destination)
    {
        var readBuffer = GetReadBuffer(destination.Length);

        var bytesReadFromInput = _plainDataInputStream.Read(readBuffer.Span);

        return EncryptIntoDestination(readBuffer.Span[..bytesReadFromInput], destination);
    }

    private async ValueTask<ReadFromInputResult> ReadFromInputAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var readBuffer = GetReadBuffer(destination.Length);

        var bytesReadFromInput = await _plainDataInputStream.ReadAsync(readBuffer, cancellationToken).ConfigureAwait(false);

        return EncryptIntoDestination(readBuffer.Span[..bytesReadFromInput], destination.Span);
    }

    private ReadFromInputResult EncryptIntoDestination(ReadOnlySpan<byte> plainDataInput, Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            return new ReadFromInputResult(plainDataInput.Length, 0);
        }

        unsafe
        {
            fixed (byte* destinationPointer = destination)
            {
                _internalOutputStream.SetSpanWriter(new SpanWriter(destinationPointer, destination.Length));

                if (plainDataInput.IsEmpty)
                {
                    _foreignWriter.WriteEnd();
                    _endWritten = true;
                }
                else
                {
                    _foreignWriter.Write(plainDataInput);
                }
            }
        }

        _overflowStream.Seek(0, SeekOrigin.Begin);

        return new ReadFromInputResult(plainDataInput.Length, (int)_internalOutputStream.Length);
    }

    private Memory<byte> GetReadBuffer(int destinationLength)
    {
        var lengthToRead = _encoding is PgpEncoding.AsciiArmor ? Math.Max(1, Base64.GetMaxDecodedFromUtf8Length(destinationLength)) : destinationLength;

        EnsureReadBufferLength(lengthToRead);

        return _readBuffer.AsMemory(0, lengthToRead);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int DrainAnyOverflow(Span<byte> destination)
    {
        var remainingInOverflowStream = _overflowStream.Length - _overflowStream.Position;
        return remainingInOverflowStream > 0 ? _overflowStream.Read(destination) : 0;
    }

    [MemberNotNull(nameof(_readBuffer))]
    private void EnsureReadBufferLength(int length)
    {
        if (_readBuffer is not null)
        {
            if (_readBuffer.Length >= length)
            {
                return;
            }

            ArrayPool<byte>.Shared.Return(_readBuffer);
        }

        _readBuffer = ArrayPool<byte>.Shared.Rent(length);
    }

    private readonly record struct ReadFromInputResult(int InputBytesRead, int BytesProduced);

    private sealed class InternalOutputStream(MemoryStream overflowStream) : Stream
    {
        private readonly MemoryStream _overflowStream = overflowStream;
        private SpanWriter _spanWriter;

        public override bool CanRead => throw new NotSupportedException();
        public override bool CanSeek => false;
        public override bool CanWrite => true;

        public override long Length => _spanWriter.NumberOfBytesWritten;

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            var numberOfBytesWritten = _spanWriter.Write(buffer, allowPartial: true);

            if (numberOfBytesWritten < buffer.Length)
            {
                _overflowStream.Write(buffer[numberOfBytesWritten..]);
            }
        }

        public void SetSpanWriter(SpanWriter spanWriter)
        {
            _spanWriter = spanWriter;
            _overflowStream.SetLength(0);
        }
    }
}
