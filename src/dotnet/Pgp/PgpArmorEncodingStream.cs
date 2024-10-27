using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpArmorEncodingStream : BaseWriteOnlyStream
{
    private readonly GoWriteCloser _goWriteCloser;

    private GCHandle _outputStreamHandle;
    private bool _isClosed;

    private PgpArmorEncodingStream(GoWriteCloser goWriteCloser, GCHandle outputStreamHandle)
    {
        _goWriteCloser = goWriteCloser;
        _outputStreamHandle = outputStreamHandle;
    }

    ~PgpArmorEncodingStream()
    {
        Dispose(false);
    }

    public static PgpArmorEncodingStream Open(Stream outputStream, PgpBlockType blockType)
    {
        var streamHandle = GCHandle.Alloc(outputStream);
        try
        {
            var goWriter = new GoExternalWriter(streamHandle);

            using var goError = GoOpen(goWriter, blockType, out var unsafeGoWriteCloserHandle);
            goError.ThrowIfFailure();

            return new PgpArmorEncodingStream(new GoWriteCloser(unsafeGoWriteCloserHandle), streamHandle);
        }
        catch
        {
            streamHandle.Free();
            throw;
        }
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            var numberOfBytesWritten = _goWriteCloser.Write(MemoryMarshal.GetReference(buffer), (nuint)buffer.Length);

            buffer = buffer[numberOfBytesWritten..];
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Write(buffer.AsSpan().Slice(offset, count));
    }

    public override void Close()
    {
        try
        {
            if (_isClosed)
            {
                return;
            }

            _isClosed = true;

            _goWriteCloser.WriteEnd();
        }
        finally
        {
            base.Close();
        }
    }

    protected override void Dispose(bool disposing)
    {
        var isNotYetDisposed = _outputStreamHandle.IsAllocated;
        if (isNotYetDisposed)
        {
            if (disposing)
            {
                _goWriteCloser.Dispose();
            }

            _outputStreamHandle.Free();
        }

        base.Dispose(disposing);
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_armor_message_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(GoExternalWriter outputWriter, PgpBlockType blockType, out nint writeCloserHandle);
}
