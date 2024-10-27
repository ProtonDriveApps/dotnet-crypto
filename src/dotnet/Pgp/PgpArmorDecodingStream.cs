using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpArmorDecodingStream : BaseReadOnlyStream
{
    private readonly GoReader _goReader;

    private GCHandle _inputStreamHandle;

    private PgpArmorDecodingStream(GoReader goReader, GCHandle inputStreamHandle)
    {
        _goReader = goReader;
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
            var interopReader = new GoExternalReader(streamHandle);
            using var goError = GoOpen(interopReader, out var unsafeGoReaderHandle);
            goError.ThrowIfFailure();

            return new PgpArmorDecodingStream(new GoReader(unsafeGoReaderHandle), streamHandle);
        }
        catch
        {
            streamHandle.Free();
            throw;
        }
    }

    public override int Read(Span<byte> buffer)
    {
        return _goReader.Read(MemoryMarshal.GetReference(buffer), (nuint)buffer.Length);
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
                _goReader.Dispose();
            }

            _inputStreamHandle.Free();
        }

        base.Dispose(disposing);
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_unarmor_message_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(GoExternalReader inputReader, out nint readerHandle);
}
