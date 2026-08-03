namespace Proton.Cryptography.Pgp.Interop;

internal sealed class ExceptionRecordingStream(Stream inner) : Stream
{
    private readonly Stream _inner = inner;

    private Exception? _lastException;

    public Exception? TakeLastException()
    {
        var exception = _lastException;
        _lastException = null;
        return exception;
    }

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => _inner.CanSeek;

    public override bool CanWrite => _inner.CanWrite;

    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override void Flush()
    {
        _inner.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        try
        {
            return _inner.Read(buffer, offset, count);
        }
        catch (Exception exception)
        {
            RecordException(exception);
            throw;
        }
    }

    public override int Read(Span<byte> buffer)
    {
        try
        {
            return _inner.Read(buffer);
        }
        catch (Exception exception)
        {
            RecordException(exception);
            throw;
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return _inner.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        _inner.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        try
        {
            _inner.Write(buffer, offset, count);
        }
        catch (Exception exception)
        {
            RecordException(exception);
            throw;
        }
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        try
        {
            _inner.Write(buffer);
        }
        catch (Exception exception)
        {
            RecordException(exception);
            throw;
        }
    }

    private void RecordException(Exception exception)
    {
        _lastException ??= exception;
    }
}
