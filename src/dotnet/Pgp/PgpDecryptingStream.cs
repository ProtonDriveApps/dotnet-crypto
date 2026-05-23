using System.Buffers;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpDecryptingStream : BaseReadOnlyStream
{
    private readonly ForeignReader _outputReader;

    private GCHandle _inputStreamHandle;
    private MemoryHandle _detachedSignatureMemoryHandle;

    private PgpDecryptingStream(ForeignReader outputReader, GCHandle inputStreamHandle, MemoryHandle detachedSignatureMemoryHandle)
    {
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
        return Open(inputStream, inputEncoding, secrets, default, default, default, default, timeProviderOverride);
    }

    public static PgpDecryptingStream Open(
        Stream inputStream,
        in DecryptionSecrets secrets,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(inputStream, inputEncoding, secrets, default, default, default, verificationKeyRing, timeProviderOverride);
    }

    public static PgpDecryptingStream Open(
        Stream inputStream,
        in DecryptionSecrets secrets,
        ReadOnlyMemory<byte> signature,
        PgpKeyRing verificationKeyRing,
        PgpEncoding inputEncoding = default,
        PgpEncoding signatureEncoding = default,
        EncryptionState signatureEncryptionState = default,
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
            timeProviderOverride);
    }

    public override int Read(Span<byte> buffer)
    {
        return _outputReader.Read(buffer);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan().Slice(offset, count));
    }

    public PgpVerificationResult GetVerificationResult()
    {
        return _outputReader.GetVerificationResult();
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
            _detachedSignatureMemoryHandle.Dispose();
        }

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
        TimeProvider? timeProviderOverride)
    {
        var (decryptionKeyRing, sessionKey, password) = secrets;

        fixed (nint* decryptionKeysPointer = decryptionKeyRing.DangerousGetForeignKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* verificationKeysPointer = verificationKeyRing.DangerousGetForeignKeyHandles())
                {
                    var detachedSignatureMemoryHandle = signature.Pin();

                    try
                    {
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
                            timeProviderOverride);

                        var streamHandle = GCHandle.Alloc(inputStream);

                        try
                        {
                            using var error = ForeignFunctions.OpenStream(
                                parameters,
                                new InteropReader(streamHandle),
                                inputEncoding.ToInteropEncoding(),
                                out var outputReaderHandle);

                            error.ThrowPgpExceptionIfAny();

                            return new PgpDecryptingStream(new ForeignReader(outputReaderHandle), streamHandle, detachedSignatureMemoryHandle);
                        }
                        catch
                        {
                            streamHandle.Free();
                            throw;
                        }
                    }
                    catch
                    {
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
