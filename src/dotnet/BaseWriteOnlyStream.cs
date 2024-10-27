namespace Proton.Cryptography;

public abstract class BaseWriteOnlyStream : Stream
{
    private bool _isDisposed;

    public sealed override bool CanRead => false;
    public sealed override bool CanSeek => false;
    public sealed override bool CanWrite => !_isDisposed;

    public sealed override long Length => throw new NotSupportedException();

    public sealed override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public sealed override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public sealed override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public sealed override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        _isDisposed = true;

        base.Dispose(disposing);
    }
}
