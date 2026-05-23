using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpArmorDecodingStream : BaseReadOnlyStream
{
    private readonly ForeignReader _outputReader;

    private GCHandle _inputStreamHandle;

    private PgpArmorDecodingStream(ForeignReader outputReader, GCHandle inputStreamHandle)
    {
        _outputReader = outputReader;
        _inputStreamHandle = inputStreamHandle;
    }

    ~PgpArmorDecodingStream()
    {
        Dispose(false);
    }

    public static PgpArmorDecodingStream Open(Stream inputStream)
    {
        var streamHandle = GCHandle.Alloc(inputStream);

        try
        {
            var inputReader = new InteropReader(streamHandle);
            using var error = ForeignFunctions.Open(inputReader, out var outputReaderHandle);
            error.ThrowPgpExceptionIfAny();

            return new PgpArmorDecodingStream(new ForeignReader(outputReaderHandle), streamHandle);
        }
        catch
        {
            streamHandle.Free();
            throw;
        }
    }

    public override int Read(Span<byte> buffer)
    {
        return _outputReader.Read(buffer);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan().Slice(offset, count));
    }

    protected override void Dispose(bool disposing)
    {
        var isNotYetDisposed = _inputStreamHandle.IsAllocated;
        if (isNotYetDisposed)
        {
            if (disposing)
            {
                _outputReader.Dispose();
            }

            _inputStreamHandle.Free();
        }

        base.Dispose(disposing);
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_unarmor_message_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError Open(InteropReader inputReader, out nint outputReaderHandle);
    }
}
