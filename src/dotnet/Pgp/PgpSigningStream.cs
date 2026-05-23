using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpSigningStream : BaseWriteOnlyStream
{
    private readonly ForeignWriter _inputWriter;

    private GCHandle _outputStreamHandle;
    private bool _isClosed;

    private PgpSigningStream(ForeignWriter inputWriter, GCHandle outputStreamHandle)
    {
        _inputWriter = inputWriter;
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
        PgpProfile profile = default,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (void* signingKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropSigningParameters(signingKeysPointer, (nuint)signingKeyRing.Count, profile, timeProviderOverride);

            var streamHandle = GCHandle.Alloc(outputStream);
            try
            {
                using var error = ForeignFunctions.OpenStream(
                    parameters,
                    InteropWriter.FromStreamHandle(streamHandle),
                    encoding.ToInteropEncoding(),
                    outputType == SigningOutputType.SignatureOnly,
                    out var inputWriterHandle);

                error.ThrowPgpExceptionIfAny();

                return new PgpSigningStream(new ForeignWriter(inputWriterHandle), streamHandle);
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
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_sign_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenStream(
            in InteropSigningParameters parameters,
            InteropWriter outputWriter,
            InteropPgpEncoding encoding,
            [MarshalAs(UnmanagedType.U1)] bool isDetached,
            out nint inputWriterHandle);
    }
}
