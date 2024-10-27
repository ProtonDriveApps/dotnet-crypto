using System.ComponentModel;

namespace Proton.Cryptography;

public sealed class AsciiStream(string text) : Stream
{
    private readonly string _text = text;
    private int _position;

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;

    public override long Length => _text.Length;

    public override long Position
    {
        get => _position;
        set
        {
            if (value > _text.Length || value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            _position = (int)value;
        }
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length, nameof(buffer));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset + count, buffer.Length, nameof(count));

        var bytesWritten = Encoding.ASCII.GetBytes(_text.AsSpan(_position, Math.Min(count, _text.Length - _position)), buffer.AsSpan(offset, count));

        _position += bytesWritten;

        return bytesWritten;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, _text.Length, nameof(offset));

        var newPosition = origin switch
        {
            SeekOrigin.Begin => (int)offset,
            SeekOrigin.Current => unchecked(_position + (int)offset),
            SeekOrigin.End => unchecked(_text.Length + (int)offset),
            _ => throw new InvalidEnumArgumentException(nameof(origin), (int)origin, typeof(SeekOrigin))
        };

        if (newPosition < 0)
        {
            throw new IOException("Cannot seek before beginning of stream.");
        }

        _position = newPosition;

        return _position;
    }

    public override void SetLength(long value) => throw new InvalidOperationException();
    public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException();
}
