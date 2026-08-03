using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpSigningStream : BaseWriteOnlyStream
{
    private readonly ForeignWriter _inputWriter;
    private readonly ExceptionRecordingStream _outputStream;

    private GCHandle _outputStreamHandle;
    private bool _isClosed;

    private PgpSigningStream(
        ForeignWriter inputWriter,
        ExceptionRecordingStream outputStream,
        GCHandle outputStreamHandle)
    {
        _inputWriter = inputWriter;
        _outputStream = outputStream;
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
        PgpSigningContext? signingContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        fixed (void* signingKeysPointer = signingKeyRing.DangerousGetForeignKeyHandles())
        {
            var parameters = new InteropSigningParameters(
                signingKeysPointer,
                (nuint)signingKeyRing.Count,
                profile,
                signingContext,
                timeProviderOverride);

            var outputRecordingStream = new ExceptionRecordingStream(outputStream);
            var outputStreamHandle = default(GCHandle);
            ForeignWriter? inputWriter = null;

            try
            {
                outputStreamHandle = GCHandle.Alloc(outputRecordingStream);

                using var error = ForeignFunctions.OpenStream(
                    parameters,
                    InteropWriter.FromStreamHandle(outputStreamHandle),
                    encoding.ToInteropEncoding(),
                    outputType == SigningOutputType.SignatureOnly,
                    out var inputWriterHandle);

                inputWriter = new ForeignWriter(inputWriterHandle);

                error.ThrowPgpOrStreamExceptionIfAny(outputRecordingStream);

                return new PgpSigningStream(inputWriter.Value, outputRecordingStream, outputStreamHandle);
            }
            catch
            {
                inputWriter?.Dispose();

                if (outputStreamHandle.IsAllocated)
                {
                    outputStreamHandle.Free();
                }

                throw;
            }
        }
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            var numberOfBytesWritten = _inputWriter.Write(buffer, _outputStream);

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

            _inputWriter.WriteEnd(_outputStream);
        }
        finally
        {
            base.Close();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inputWriter.Dispose();
        }

        if (_outputStreamHandle.IsAllocated)
        {
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
