using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpArmorEncodingStream : BaseWriteOnlyStream
{
    private readonly ForeignWriter _inputWriter;

    private GCHandle _outputStreamHandle;
    private bool _isClosed;

    private PgpArmorEncodingStream(ForeignWriter inputWriter, GCHandle outputStreamHandle)
    {
        _inputWriter = inputWriter;
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
            var outputWriter = InteropWriter.FromStreamHandle(streamHandle);

            using var error = ForeignFunctions.OpenStream(outputWriter, blockType, out var inputWriterHandle);
            error.ThrowPgpExceptionIfAny();

            return new PgpArmorEncodingStream(new ForeignWriter(inputWriterHandle), streamHandle);
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
            var numberOfBytesWritten = _inputWriter.Write(buffer);

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

            _inputWriter.WriteEnd();
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
                _inputWriter.Dispose();
            }

            _outputStreamHandle.Free();
        }

        base.Dispose(disposing);
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_armor_message_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenStream(InteropWriter outputWriter, PgpBlockType blockType, out nint inputWriterHandle);
    }
}
