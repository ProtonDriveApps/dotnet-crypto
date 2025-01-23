using System.Buffers;
using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpDecryptingStream : BaseReadOnlyStream
{
    private readonly GoReader _goReader;

    private GCHandle _inputStreamHandle;
    private MemoryHandle _detachedSignatureMemoryHandle;

    private PgpDecryptingStream(GoReader goReader, GCHandle inputStreamHandle, MemoryHandle detachedSignatureMemoryHandle)
    {
        _goReader = goReader;
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
        return _goReader.Read(MemoryMarshal.GetReference(buffer), (nuint)buffer.Length);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan().Slice(offset, count));
    }

    public PgpVerificationResult GetVerificationResult()
    {
        using var goError = GoGetVerificationResult(_goReader, out var unsafeHandle);
        goError.ThrowIfFailure();

        return new PgpVerificationResult(new GoVerificationResult(unsafeHandle));
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
        PgpKeyRing goVerificationKeyRing,
        TimeProvider? timeProviderOverride)
    {
        var (decryptionKeyRing, sessionKey, password) = secrets;

        fixed (nint* goDecryptionKeysPointer = decryptionKeyRing.DangerousGetGoKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* goVerificationKeysPointer = goVerificationKeyRing.DangerousGetGoKeyHandles())
                {
                    var detachedSignatureMemoryHandle = signature.Pin();

                    try
                    {
                        var parameters = new GoDecryptionParameters(
                            goDecryptionKeysPointer,
                            (nuint)decryptionKeyRing.Count,
                            goVerificationKeysPointer,
                            (nuint)goVerificationKeyRing.Count,
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
                            var interopReader = new GoExternalReader(streamHandle);
                            using var goError = GoOpen(parameters, interopReader, inputEncoding.ToGoEncoding(), out var unsafeGoReaderHandle);
                            goError.ThrowIfFailure();

                            return new PgpDecryptingStream(new GoReader(unsafeGoReaderHandle), streamHandle, detachedSignatureMemoryHandle);
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

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_decrypt_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoDecryptionParameters parameters,
        GoExternalReader inputReader,
        GoPgpEncoding encoding,
        out nint readerHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_verification_reader_get_verify_result")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoGetVerificationResult(GoReader goReader, out nint verificationResultHandle);
}
