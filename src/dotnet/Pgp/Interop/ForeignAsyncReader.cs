using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class ForeignAsyncReader() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    private readonly SemaphoreSlim _readerGate = new(1, 1);

    public ForeignAsyncReader(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public int Read(scoped ref byte buffer, int bufferLength, params ReadOnlySpan<ExceptionRecordingStream?> streams)
    {
        ObjectDisposedException.ThrowIf(IsInvalid, this);

        _readerGate.Wait();

        try
        {
            using var error = ForeignFunctions.ReadBlocking(this, ref buffer, (nuint)bufferLength, out var numberOfBytesRead);

            error.ThrowPgpOrStreamExceptionIfAny(streams);

            return (int)numberOfBytesRead;
        }
        finally
        {
            _readerGate.Release();
        }
    }

    public async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken,
        ExceptionRecordingStream? plainDataInputStream,
        ExceptionRecordingStream? keyPacketRecordingStream,
        ExceptionRecordingStream? signatureRecordingStream)
    {
        ObjectDisposedException.ThrowIf(IsInvalid, this);

        await _readerGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            using var pin = buffer.Pin();

            var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            var userContext = GCHandle.Alloc(completion);
            InteropError error;
            unsafe
            {
                error = ForeignFunctions.ReadAsyncNative(
                    this,
                    (byte*)pin.Pointer,
                    (nuint)buffer.Length,
                    GCHandle.ToIntPtr(userContext),
                    &OnEncryptReaderReadComplete);
            }

            if (error.Any)
            {
                userContext.Free();
                error.ThrowPgpOrStreamExceptionIfAny(plainDataInputStream, keyPacketRecordingStream, signatureRecordingStream);
            }

            try
            {
                return await completion.Task.ConfigureAwait(false);
            }
            catch (PgpException)
            {
                ExceptionRecordingStream.ThrowIfAnyException(plainDataInputStream, keyPacketRecordingStream, signatureRecordingStream);
                throw;
            }
        }
        finally
        {
            _readerGate.Release();
        }
    }

    protected override bool ReleaseHandle()
    {
        _readerGate.Wait();

        try
        {
            ForeignFunctions.DestroyHandle(handle);

            return true;
        }
        finally
        {
            _readerGate.Release();
            _readerGate.Dispose();
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe void OnEncryptReaderReadComplete(GCHandle completionHandle, nuint bytesRead, InteropError* error)
    {
        var completion = (TaskCompletionSource<int>)completionHandle.Target!;
        completionHandle.Free();

        if (error != null && error->TryGetMessage(out var failureMessage))
        {
            error->Dispose();

            try
            {
                completion.TrySetException(new PgpException(failureMessage));
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }

            return;
        }

        completion.TrySetResult((int)bytesRead);
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_reader_read_blocking")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError ReadBlocking(
            ForeignAsyncReader nativeReader,
            ref byte buffer,
            nuint bufferLength,
            out nuint numberOfBytesRead);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_reader_read_async")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError ReadAsyncNative(
            ForeignAsyncReader nativeReader,
            byte* buffer,
            nuint bufferLength,
            nint userContext,
            delegate* unmanaged[Cdecl]<GCHandle, nuint, InteropError*, void> complete);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_encrypt_reader_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void DestroyHandle(nint handle);
    }
}
