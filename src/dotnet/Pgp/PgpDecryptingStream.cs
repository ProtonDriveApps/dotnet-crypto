using System.Buffers;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpDecryptingStream : BaseReadOnlyStream
{
    private readonly ExceptionRecordingStream _inputStream;
    private readonly ForeignReader _outputReader;

    private GCHandle _inputStreamHandle;
    private MemoryHandle _detachedSignatureMemoryHandle;

    private PgpDecryptingStream(
        ExceptionRecordingStream inputStream,
        ForeignReader outputReader,
        GCHandle inputStreamHandle,
        MemoryHandle detachedSignatureMemoryHandle)
    {
        _inputStream = inputStream;
        _outputReader = outputReader;
        _inputStreamHandle = inputStreamHandle;
        _detachedSignatureMemoryHandle = detachedSignatureMemoryHandle;
    }

    ~PgpDecryptingStream()
    {
        Dispose(false);
    }

    public static PgpDecryptingStream Open(
        Stream inputStream,
        in DecryptionSecrets secrets,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(inputStream, inputEncoding, secrets, default, default, default, default, null, timeProviderOverride);
    }

    public static PgpDecryptingStream Open(
        Stream inputStream,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        PgpVerificationContext? verificationContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(inputStream, inputEncoding, secrets, default, default, default, verificationKeyRing, verificationContext, timeProviderOverride);
    }

    public static PgpDecryptingStream Open(
        Stream inputStream,
        in DecryptionSecrets secrets,
        ReadOnlyMemory<byte> signature,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
        PgpVerificationContext? verificationContext = null,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(
            inputStream,
            inputEncoding,
            secrets,
            signature,
            signatureEncoding,
            signatureEncryptionState,
            verificationKeyRing,
            verificationContext,
            timeProviderOverride);
    }

    public override int Read(Span<byte> buffer)
    {
        return _outputReader.Read(buffer, _inputStream);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan().Slice(offset, count));
    }

    public PgpVerificationResult GetVerificationResult()
    {
        return _outputReader.GetVerificationResult(_inputStream);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_inputStreamHandle.IsAllocated)
        {
            return;
        }

        if (disposing)
        {
            _outputReader.Dispose();
        }

        _inputStreamHandle.Free();
        _detachedSignatureMemoryHandle.Dispose();

        base.Dispose(disposing);
    }

    private static unsafe PgpDecryptingStream Open(
        Stream inputStream,
        PgpEncoding inputEncoding,
        in DecryptionSecrets secrets,
        ReadOnlyMemory<byte> signature,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        PgpKeyRing verificationKeyRing,
        PgpVerificationContext? verificationContext,
        TimeProvider? timeProviderOverride)
    {
        var (decryptionKeyRing, sessionKey, password) = secrets;

        fixed (nint* decryptionKeysPointer = decryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* verificationKeysPointer = verificationKeyRing.DangerousGetForeignKeyHandles())
                {
                    var inputRecordingStream = new ExceptionRecordingStream(inputStream);
                    var detachedSignatureMemoryHandle = signature.Pin();
                    var inputStreamHandle = default(GCHandle);
                    ForeignReader? outputReader = null;

                    try
                    {
                        inputStreamHandle = GCHandle.Alloc(inputRecordingStream);

                        var parameters = new InteropDecryptionParameters(
                            decryptionKeysPointer,
                            (nuint)decryptionKeyRing.Count,
                            verificationKeysPointer,
                            (nuint)verificationKeyRing.Count,
                            sessionKey,
                            passwordPointer,
                            (nuint)password.Length,
                            (byte*)detachedSignatureMemoryHandle.Pointer,
                            (nuint)signature.Length,
                            signatureEncoding,
                            signatureEncryptionState,
                            verificationContext,
                            timeProviderOverride);

                        using var error = ForeignFunctions.OpenStream(
                            parameters,
                            new InteropReader(inputStreamHandle),
                            inputEncoding.ToInteropEncoding(),
                            out var outputReaderHandle);

                        outputReader = new ForeignReader(outputReaderHandle);

                        error.ThrowPgpOrStreamExceptionIfAny(inputRecordingStream);

                        return new PgpDecryptingStream(
                            inputRecordingStream,
                            outputReader.Value,
                            inputStreamHandle,
                            detachedSignatureMemoryHandle);
                    }
                    catch
                    {
                        outputReader?.Dispose();

                        if (inputStreamHandle.IsAllocated)
                        {
                            inputStreamHandle.Free();
                        }

                        detachedSignatureMemoryHandle.Dispose();
                        throw;
                    }
                }
            }
        }
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_decrypt_stream")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError OpenStream(
            in InteropDecryptionParameters parameters,
            InteropReader inputReader,
            InteropPgpEncoding encoding,
            out nint outputReaderHandle);
    }
}
