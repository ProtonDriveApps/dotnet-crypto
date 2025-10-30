using System.Buffers;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public partial class PgpEncryptingStream : Stream
{
    private GoEncryptionStream _goStream;

    private bool _endWritten;

    private PgpEncryptingStream(GoEncryptionStream goStream)
    {
        _goStream = goStream;
    }

    ~PgpEncryptingStream()
    {
        Dispose(false);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => _goStream.CanWrite;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var goStream = CreateGoStream(
            messageOutputStream,
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            encryptionSecrets,
            default,
            encoding,
            compression,
            default,
            profile,
            timeProviderOverride);

        return new PgpEncryptingStream(goStream);
    }

    public static PgpEncryptingStream OpenRead(
        Stream plainDataInputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        return ReadModeStream.Create(plainDataInputStream, encryptionSecrets, encoding, compression, profile, timeProviderOverride);
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var goStream = CreateGoStream(
            messageOutputStream,
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            encryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            default,
            profile,
            timeProviderOverride);

        return new PgpEncryptingStream(goStream);
    }

    public static PgpEncryptingStream OpenRead(
        Stream plainDataInputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        return ReadModeStream.Create(plainDataInputStream, encryptionSecrets, signingKeyRing, encoding, compression, profile, timeProviderOverride);
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
        try
        {
            var goSignatureWriter = GoExternalWriter.FromStreamHandle(signatureOutputStreamHandle);

            var goStream = CreateGoStream(
                messageOutputStream,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                signatureOutputStreamHandle,
                goSignatureWriter,
                encryptionSecrets,
                signingKeyRing,
                encoding,
                messageCompression,
                signatureEncryptionState,
                profile,
                timeProviderOverride);

            return new PgpEncryptingStream(goStream);
        }
        catch
        {
            signatureOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingStream OpenRead(
        Stream plainDataInputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        return ReadModeStream.Create(
            plainDataInputStream,
            signatureOutputStream,
            encryptionSecrets,
            signingKeyRing,
            encoding,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var goKeyPacketWriter = GoExternalWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var goStream = CreateGoStream(
                messageOutputStream,
                keyPacketOutputStreamHandle,
                goKeyPacketWriter,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                encryptionSecrets,
                default,
                default,
                messageCompression,
                default,
                profile,
                timeProviderOverride);

            return new PgpEncryptingStream(goStream);
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingStream OpenSplitRead(
        Stream plainDataInputStream,
        Stream keyPacketsOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpCompression messageCompression = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        return ReadModeStream.CreateSplit(
            plainDataInputStream,
            keyPacketsOutputStream,
            encryptionSecrets,
            messageCompression,
            profile,
            timeProviderOverride);
    }

    public static PgpEncryptingStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var goKeyPacketWriter = GoExternalWriter.FromStreamHandle(keyPacketOutputStreamHandle);

            var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
            try
            {
                var goSignatureWriter = GoExternalWriter.FromStreamHandle(signatureOutputStreamHandle);

                var goStream = CreateGoStream(
                    messageOutputStream,
                    keyPacketOutputStreamHandle,
                    goKeyPacketWriter,
                    signatureOutputStreamHandle,
                    goSignatureWriter,
                    encryptionSecrets,
                    signingKeyRing,
                    default,
                    messageCompression,
                    signatureEncryptionState,
                    profile,
                    timeProviderOverride);

                return new PgpEncryptingStream(goStream);
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

    public static PgpEncryptingStream OpenSplitRead(
        Stream plainDataInputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        return ReadModeStream.CreateSplit(
            plainDataInputStream,
            keyPacketsOutputStream,
            signatureOutputStream,
            encryptionSecrets,
            signingKeyRing,
            messageCompression,
            signatureEncryptionState,
            profile,
            timeProviderOverride);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _goStream.Write(buffer);
    }

    public override void Close()
    {
        try
        {
            if (_endWritten)
            {
                return;
            }

            _goStream.WriteEnd();

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
            _goStream.Dispose();
        }

        base.Dispose(disposing);
    }

    private static unsafe GoEncryptionStream CreateGoStream(
        Stream messageOutputStream,
        GCHandle? keyPacketOutputStreamHandle,
        in GoExternalWriter goKeyPacketWriter,
        GCHandle? signatureOutputStreamHandle,
        in GoExternalWriter goSignatureWriter,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding,
        PgpCompression dataCompression,
        EncryptionState signatureEncryptionState,
        PgpProfile profile,
        TimeProvider? timeProviderOverride)
    {
        var (goEncryptionKeyRing, sessionKey, password) = encryptionSecrets;

        fixed (nint* goEncryptionKeysPointer = goEncryptionKeyRing.DangerousGetGoKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* goSigningKeysPointer = signingKeyRing.DangerousGetGoKeyHandles())
                {
                    var parameters = new GoEncryptionParameters(
                        profile,
                        goEncryptionKeysPointer,
                        (nuint)goEncryptionKeyRing.Count,
                        goSigningKeysPointer,
                        (nuint)signingKeyRing.Count,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        signatureOutputStreamHandle.HasValue,
                        signatureEncryptionState == EncryptionState.Encrypted,
                        dataCompression != PgpCompression.None,
                        0,
                        timeProviderOverride);

                    var messageOutputStreamHandle = GCHandle.Alloc(messageOutputStream);
                    try
                    {
                        var goWriter = GoExternalWriter.FromStreamHandle(messageOutputStreamHandle);
                        var goEncoding = encoding.ToGoEncoding();

                        using var goError = Unsafe.IsNullRef(in goKeyPacketWriter)
                            ? GoOpen(parameters, goWriter, goSignatureWriter, goEncoding, out var unsafeGoWriteCloserHandle)
                            : GoOpen(parameters, goWriter, goSignatureWriter, goKeyPacketWriter, out unsafeGoWriteCloserHandle);

                        goError.ThrowIfFailure();

#pragma warning disable CA2000 // False positive: ownership is transferred to another disposable
                        var goWriteCloser = new GoWriteCloser(unsafeGoWriteCloserHandle);
#pragma warning restore CA2000

                        return new GoEncryptionStream(
                            goWriteCloser,
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

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoEncryptionParameters parameters,
        GoExternalWriter outputWriter,
        in GoExternalWriter signatureWriter,
        GoPgpEncoding encoding,
        out nint writeCloserHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt_stream_split")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoEncryptionParameters parameters,
        GoExternalWriter outputWriter,
        in GoExternalWriter signatureWriter,
        GoExternalWriter keyPacketWriter,
        out nint writeCloserHandle);

    private struct GoEncryptionStream(
        GoWriteCloser goWriteCloser,
        GCHandle dataOutputStreamHandle,
        GCHandle? keyPacketOutputStreamHandle,
        GCHandle? signatureOutputStreamHandle) : IDisposable
    {
        private readonly GoWriteCloser _goWriteCloser = goWriteCloser;
        private readonly GCHandle? _keyPacketOutputStreamHandle = keyPacketOutputStreamHandle;
        private readonly GCHandle? _signatureOutputStreamHandle = signatureOutputStreamHandle;
        private GCHandle _dataOutputStreamHandle = dataOutputStreamHandle;

        public bool CanWrite => _dataOutputStreamHandle.IsAllocated;

        public readonly void Write(ReadOnlySpan<byte> buffer)
        {
            while (buffer.Length > 0)
            {
                var numberOfBytesWritten = _goWriteCloser.Write(MemoryMarshal.GetReference(buffer), (nuint)buffer.Length);

                buffer = buffer[numberOfBytesWritten..];
            }
        }

        public readonly void WriteEnd()
        {
            _goWriteCloser.WriteEnd();
        }

        public void Dispose()
        {
            var isAlreadyDisposed = !_dataOutputStreamHandle.IsAllocated;
            if (isAlreadyDisposed)
            {
                return;
            }

            _goWriteCloser.Dispose();
            _dataOutputStreamHandle.Free();
            _keyPacketOutputStreamHandle?.Free();
            _signatureOutputStreamHandle?.Free();
        }
    }

    private sealed class ReadModeStream : PgpEncryptingStream
    {
        private const int OverflowBufferLength = 8192;

        private readonly Stream _plainDataInputStream;
        private readonly InternalOutputStream _internalOutputStream;
        private readonly MemoryStream _overflowStream;
        private readonly PgpEncoding _encoding;

        private byte[]? _readBuffer;

        private ReadModeStream(
            GoEncryptionStream goStream,
            Stream plainDataInputStream,
            InternalOutputStream internalOutputStream,
            MemoryStream overflowStream,
            PgpEncoding encoding)
            : base(goStream)
        {
            _plainDataInputStream = plainDataInputStream;
            _internalOutputStream = internalOutputStream;
            _overflowStream = overflowStream;
            _encoding = encoding;

            _overflowStream.Seek(0, SeekOrigin.Begin);
        }

        public override bool CanRead => base.CanWrite;
        public override bool CanWrite => false;

        public static PgpEncryptingStream Create(
            Stream plainDataInputStream,
            in EncryptionSecrets encryptionSecrets,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            TimeProvider? timeProviderOverride = null)
        {
            var overflowStream = new MemoryStream(OverflowBufferLength);
            var internalOutputStream = new InternalOutputStream(overflowStream);

            var goStream = CreateGoStream(
                internalOutputStream,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                encryptionSecrets,
                default,
                encoding,
                compression,
                default,
                profile,
                timeProviderOverride);

            return new ReadModeStream(goStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
        }

        public static PgpEncryptingStream Create(
            Stream plainDataInputStream,
            in EncryptionSecrets encryptionSecrets,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression compression = default,
            PgpProfile profile = default,
            TimeProvider? timeProviderOverride = null)
        {
            var overflowStream = new MemoryStream(OverflowBufferLength);
            var internalOutputStream = new InternalOutputStream(overflowStream);

            var goStream = CreateGoStream(
                internalOutputStream,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                encryptionSecrets,
                signingKeyRing,
                encoding,
                compression,
                default,
                profile,
                timeProviderOverride);

            return new ReadModeStream(goStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
        }

        public static PgpEncryptingStream Create(
            Stream plainDataInputStream,
            Stream signatureOutputStream,
            in EncryptionSecrets encryptionSecrets,
            PgpPrivateKeyRing signingKeyRing,
            PgpEncoding encoding = default,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            TimeProvider? timeProviderOverride = null)
        {
            var overflowStream = new MemoryStream(OverflowBufferLength);
            var internalOutputStream = new InternalOutputStream(overflowStream);

            var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
            try
            {
                var goSignatureWriter = GoExternalWriter.FromStreamHandle(signatureOutputStreamHandle);

                var goStream = CreateGoStream(
                    internalOutputStream,
                    null,
                    Unsafe.NullRef<GoExternalWriter>(),
                    signatureOutputStreamHandle,
                    goSignatureWriter,
                    encryptionSecrets,
                    signingKeyRing,
                    encoding,
                    messageCompression,
                    signatureEncryptionState,
                    profile,
                    timeProviderOverride);

                return new ReadModeStream(goStream, plainDataInputStream, internalOutputStream, overflowStream, encoding);
            }
            catch
            {
                signatureOutputStreamHandle.Free();
                throw;
            }
        }

        public static PgpEncryptingStream CreateSplit(
            Stream plainDataInputStream,
            Stream keyPacketsOutputStream,
            in EncryptionSecrets encryptionSecrets,
            PgpCompression messageCompression = default,
            PgpProfile profile = default,
            TimeProvider? timeProviderOverride = null)
        {
            var overflowStream = new MemoryStream(OverflowBufferLength);
            var internalOutputStream = new InternalOutputStream(overflowStream);

            var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
            try
            {
                var goKeyPacketWriter = GoExternalWriter.FromStreamHandle(keyPacketOutputStreamHandle);

                var goStream = CreateGoStream(
                    internalOutputStream,
                    keyPacketOutputStreamHandle,
                    goKeyPacketWriter,
                    null,
                    Unsafe.NullRef<GoExternalWriter>(),
                    encryptionSecrets,
                    default,
                    default,
                    messageCompression,
                    default,
                    profile,
                    timeProviderOverride);

                return new ReadModeStream(goStream, plainDataInputStream, internalOutputStream, overflowStream, default);
            }
            catch
            {
                keyPacketOutputStreamHandle.Free();
                throw;
            }
        }

        public static PgpEncryptingStream CreateSplit(
            Stream plainDataInputStream,
            Stream keyPacketsOutputStream,
            Stream signatureOutputStream,
            in EncryptionSecrets encryptionSecrets,
            PgpPrivateKeyRing signingKeyRing,
            PgpCompression messageCompression = default,
            EncryptionState signatureEncryptionState = default,
            PgpProfile profile = default,
            TimeProvider? timeProviderOverride = null)
        {
            var overflowStream = new MemoryStream(OverflowBufferLength);
            var internalOutputStream = new InternalOutputStream(overflowStream);

            var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
            try
            {
                var goKeyPacketWriter = GoExternalWriter.FromStreamHandle(keyPacketOutputStreamHandle);

                var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
                try
                {
                    var goSignatureWriter = GoExternalWriter.FromStreamHandle(signatureOutputStreamHandle);

                    var goStream = CreateGoStream(
                        internalOutputStream,
                        keyPacketOutputStreamHandle,
                        goKeyPacketWriter,
                        signatureOutputStreamHandle,
                        goSignatureWriter,
                        encryptionSecrets,
                        signingKeyRing,
                        default,
                        messageCompression,
                        signatureEncryptionState,
                        profile,
                        timeProviderOverride);

                    return new ReadModeStream(goStream, plainDataInputStream, internalOutputStream, overflowStream, default);
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

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            throw new NotSupportedException("Stream is read-only");
        }

        protected override void Dispose(bool disposing)
        {
            if (_readBuffer is not null)
            {
                CryptographicOperations.ZeroMemory(_readBuffer);
                ArrayPool<byte>.Shared.Return(_readBuffer);
                _readBuffer = null;
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
                        _goStream.WriteEnd();
                        _endWritten = true;
                    }
                    else
                    {
                        base.Write(plainDataInput);
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
    }

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
