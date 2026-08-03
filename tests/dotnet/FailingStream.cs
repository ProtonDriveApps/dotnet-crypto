namespace Proton.Cryptography.Tests;

internal sealed class FailingStream(Stream inner, long failWhenPositionExceeds, Func<Exception> createException) : Stream
{
    private readonly long _failWhenPositionExceeds = failWhenPositionExceeds;
    private readonly Func<Exception> _createException = createException;

    public override bool CanRead => inner.CanRead;

    public override bool CanSeek => inner.CanSeek;

    public override bool CanWrite => inner.CanWrite;

    public override long Length => inner.Length;

    public override long Position
    {
        get => inner.Position;
        set => inner.Position = value;
    }

    public override void Flush()
    {
        inner.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ThrowIfShouldFail();

        return inner.Read(buffer, offset, count);
    }

    public override int Read(Span<byte> buffer)
    {
        ThrowIfShouldFail();

        return inner.Read(buffer);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return inner.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        inner.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ThrowIfShouldFail();

        inner.Write(buffer);
    }

    private void ThrowIfShouldFail()
    {
        if (inner.Position >= _failWhenPositionExceeds)
        {
            throw _createException.Invoke();
        }
    }
}
