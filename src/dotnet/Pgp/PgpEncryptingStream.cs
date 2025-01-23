using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public sealed partial class PgpEncryptingStream : BaseWriteOnlyStream
{
    private readonly GoWriteCloser _goWriteCloser;

    private readonly GCHandle? _signatureOutputStreamHandle;
    private readonly GCHandle? _keyPacketOutputStreamHandle;

    private GCHandle _dataOutputStreamHandle;
    private bool _isClosed;

    private PgpEncryptingStream(
        GoWriteCloser goWriteCloser,
        GCHandle dataOutputStreamHandle,
        GCHandle? keyPacketOutputStreamHandle,
        GCHandle? signatureOutputStreamHandle)
    {
        _goWriteCloser = goWriteCloser;
        _dataOutputStreamHandle = dataOutputStreamHandle;
        _keyPacketOutputStreamHandle = keyPacketOutputStreamHandle;
        _signatureOutputStreamHandle = signatureOutputStreamHandle;
    }

    ~PgpEncryptingStream()
    {
        Dispose(false);
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(
            messageOutputStream,
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            encryptionSecrets,
            default,
            encoding,
            compression,
            default,
            timeProviderOverride);
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression compression = default,
        TimeProvider? timeProviderOverride = null)
    {
        return Open(
            messageOutputStream,
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            null,
            Unsafe.NullRef<GoExternalWriter>(),
            encryptionSecrets,
            signingKeyRing,
            encoding,
            compression,
            default,
            timeProviderOverride);
    }

    public static PgpEncryptingStream Open(
        Stream messageOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding = default,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
    {
        var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
        try
        {
            var goSignatureWriter = new GoExternalWriter(signatureOutputStreamHandle);

            return Open(
                messageOutputStream,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                signatureOutputStreamHandle,
                goSignatureWriter,
                encryptionSecrets,
                signingKeyRing,
                encoding,
                messageCompression,
                signatureEncryptionState,
                timeProviderOverride);
        }
        catch
        {
            signatureOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpCompression messageCompression = default,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var goKeyPacketWriter = new GoExternalWriter(keyPacketOutputStreamHandle);

            return Open(
                messageOutputStream,
                keyPacketOutputStreamHandle,
                goKeyPacketWriter,
                null,
                Unsafe.NullRef<GoExternalWriter>(),
                encryptionSecrets,
                default,
                default,
                messageCompression,
                default,
                timeProviderOverride);
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
            throw;
        }
    }

    public static PgpEncryptingStream OpenSplit(
        Stream messageOutputStream,
        Stream keyPacketsOutputStream,
        Stream signatureOutputStream,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpCompression messageCompression = default,
        EncryptionState signatureEncryptionState = default,
        TimeProvider? timeProviderOverride = null)
    {
        var keyPacketOutputStreamHandle = GCHandle.Alloc(keyPacketsOutputStream);
        try
        {
            var goKeyPacketWriter = new GoExternalWriter(keyPacketOutputStreamHandle);

            var signatureOutputStreamHandle = GCHandle.Alloc(signatureOutputStream);
            try
            {
                var goSignatureWriter = new GoExternalWriter(signatureOutputStreamHandle);

                return Open(
                    messageOutputStream,
                    keyPacketOutputStreamHandle,
                    goKeyPacketWriter,
                    signatureOutputStreamHandle,
                    goSignatureWriter,
                    encryptionSecrets,
                    signingKeyRing,
                    default,
                    messageCompression,
                    signatureEncryptionState,
                    timeProviderOverride);
            }
            catch
            {
                signatureOutputStreamHandle.Free();
                throw;
            }
        }
        catch
        {
            keyPacketOutputStreamHandle.Free();
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
        var isNotYetDisposed = _dataOutputStreamHandle.IsAllocated;
        if (isNotYetDisposed)
        {
            if (disposing)
            {
                _goWriteCloser.Dispose();
            }

            _dataOutputStreamHandle.Free();
            _keyPacketOutputStreamHandle?.Free();
            _signatureOutputStreamHandle?.Free();
        }

        base.Dispose(disposing);
    }

    private static unsafe PgpEncryptingStream Open(
        Stream messageOutputStream,
        GCHandle? keyPacketOutputStreamHandle,
        in GoExternalWriter goKeyPacketWriter,
        GCHandle? signatureOutputStreamHandle,
        in GoExternalWriter goSignatureWriter,
        in EncryptionSecrets encryptionSecrets,
        PgpPrivateKeyRing signingKeyRing,
        PgpEncoding encoding,
        PgpCompression dataCompression,
        EncryptionState signatureEncryptionState,
        TimeProvider? timeProviderOverride)
    {
        var (goEncryptionKeyRing, sessionKey, password) = encryptionSecrets;

        fixed (nint* goEncryptionKeysPointer = goEncryptionKeyRing.DangerousGetGoKeyHandles())
        {
            fixed (byte* passwordPointer = password)
            {
                fixed (nint* goSigningKeysPointer = signingKeyRing.DangerousGetGoKeyHandles())
                {
                    var parameters = new GoEncryptionParameters(
                        goEncryptionKeysPointer,
                        (nuint)goEncryptionKeyRing.Count,
                        goSigningKeysPointer,
                        (nuint)signingKeyRing.Count,
                        sessionKey,
                        passwordPointer,
                        (nuint)password.Length,
                        signatureOutputStreamHandle.HasValue,
                        signatureEncryptionState == EncryptionState.Encrypted,
                        dataCompression != PgpCompression.None,
                        timeProviderOverride);

                    var streamHandle = GCHandle.Alloc(messageOutputStream);
                    try
                    {
                        var goWriter = new GoExternalWriter(streamHandle);
                        var goEncoding = encoding.ToGoEncoding();

                        using var goError = Unsafe.IsNullRef(in goKeyPacketWriter)
                            ? GoOpen(parameters, goWriter, goSignatureWriter, goEncoding, out var unsafeGoWriteCloserHandle)
                            : GoOpen(parameters, goWriter, goSignatureWriter, goKeyPacketWriter, out unsafeGoWriteCloserHandle);

                        goError.ThrowIfFailure();

                        var goWriteCloser = new GoWriteCloser(unsafeGoWriteCloserHandle);

                        return new PgpEncryptingStream(goWriteCloser, streamHandle, keyPacketOutputStreamHandle, signatureOutputStreamHandle);
                    }
                    catch
                    {
                        streamHandle.Free();
                        throw;
                    }
                }
            }
        }
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt_stream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoEncryptionParameters parameters,
        GoExternalWriter outputWriter,
        in GoExternalWriter signatureWriter,
        GoPgpEncoding encoding,
        out nint writeCloserHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_encrypt_stream_split")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoOpen(
        in GoEncryptionParameters parameters,
        GoExternalWriter outputWriter,
        in GoExternalWriter signatureWriter,
        GoExternalWriter keyPacketWriter,
        out nint writeCloserHandle);
}
