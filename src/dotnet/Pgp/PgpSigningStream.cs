using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpSigningStream : BaseWriteOnlyStream
{
    private readonly GoWriteCloser _goWriteCloser;

    private GCHandle _outputStreamHandle;
    private bool _isClosed;

    private PgpSigningStream(GoWriteCloser goWriteCloser, GCHandle outputStreamHandle)
    {
        _goWriteCloser = goWriteCloser;
        _outputStreamHandle = outputStreamHandle;
    }

    ~PgpSigningStream()
    {
        Dispose(false);
    }

    public static unsafe PgpSigningStream Open(
        Stream outputStream,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        SigningOutputType outputType = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (void* goSigningKeysPointer = signingKeyRing.DangerousGetGoKeyHandles())
        {
            var parameters = new GoSigningParameters(goSigningKeysPointer, (nuint)signingKeyRing.Count, timeProviderOverride);

            var streamHandle = GCHandle.Alloc(outputStream);
            try
            {
                using var goError = GoOpen(
                    parameters,
                    new GoExternalWriter(streamHandle),
                    encoding.ToGoEncoding(),
                    outputType == SigningOutputType.SignatureOnly,
                    out var unsafeGoWriteCloserHandle);
                goError.ThrowIfFailure();

                return new PgpSigningStream(new GoWriteCloser(unsafeGoWriteCloserHandle), streamHandle);
            }
            catch
            {
                streamHandle.Free();
                throw;
            }
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

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_sign_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoSigningParameters parameters,
        GoExternalWriter outputWriter,
        GoPgpEncoding encoding,
        [MarshalAs(UnmanagedType.U1)] bool isDetached,
        out nint writeCloserHandle);
}
