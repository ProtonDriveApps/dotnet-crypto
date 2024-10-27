using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal sealed partial class GoKey() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    public GoKey(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public int Version => GoGetVersion(this);
    public nint Id => GoGetId(this);
    public bool CanEncrypt => GoGetCanEncrypt(this);
    public bool CanVerify => GoGetCanVerify(this);
    public bool IsExpired => GoGetIsExpired(this);
    public bool IsRevoked => GoGetIsRevoked(this);

    public ref nint DangerousGetHandleRef() => ref handle;

    public void Export(Stream stream, PgpEncoding encoding)
    {
        var streamHandle = GCHandle.Alloc(stream);

        try
        {
            var goWriter = new GoExternalWriter(streamHandle);

            using var goError = GoExport(this, forcePublic: false, encoding == PgpEncoding.AsciiArmor, goWriter);
            goError.ThrowIfFailure();
        }
        finally
        {
            streamHandle.Free();
        }
    }

    public unsafe byte[] GetFingerprint()
    {
        GoGetFingerprintBytes(this, out var fingerprintBytesPointer, out var fingerprintLength);

        if (fingerprintBytesPointer == null)
        {
            throw new PgpException("Could not get key fingerprint");
        }

        return CMemory.ConvertToArray<byte>(fingerprintBytesPointer, fingerprintLength);
    }

    public unsafe string[] GetSha256Fingerprints()
    {
        var goResult = GoGetSha256Fingerprints(this);

        var exception = default(Exception?);
        try
        {
            var result = new string[goResult.NumberOfFingerprints];
            for (var i = 0; i < goResult.NumberOfFingerprints; ++i)
            {
                var currentFingerprintPointer = *(goResult.Fingerprints + i);
                try
                {
                    result[i] = new string(currentFingerprintPointer);
                }
                catch (Exception e)
                {
                    exception = e;
                }
                finally
                {
                    CMemory.Free(currentFingerprintPointer);
                }
            }

            if (exception is not null)
            {
                throw new CryptographicException("Error while getting key SHA256 fingerprints", exception);
            }

            return result;
        }
        finally
        {
            CMemory.Free(goResult.Fingerprints);
        }
    }

    public override string ToString()
    {
        using var stream = new MemoryStream();

        Export(stream, PgpEncoding.AsciiArmor);

        stream.Seek(0, SeekOrigin.Begin);

        using var reader = new StreamReader(stream, Encoding.ASCII);

        return reader.ReadToEnd();
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_export")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoExport(
        GoKey goKey,
        [MarshalAs(UnmanagedType.U1)] bool forcePublic,
        [MarshalAs(UnmanagedType.U1)] bool armored,
        GoExternalWriter outputWriter);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_get_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GoGetVersion(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_get_key_id")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial nint GoGetId(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_get_fingerprint_bytes")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial void GoGetFingerprintBytes(GoKey goKey, out byte* fingerprintBytes, out nuint fingerprintLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_get_sha256_fingerprints")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GetSha256FingerprintsResult GoGetSha256Fingerprints(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_can_verify")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool GoGetCanEncrypt(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_can_verify")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool GoGetCanVerify(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_is_expired")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool GoGetIsExpired(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_is_revoked")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool GoGetIsRevoked(GoKey goKey);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "pgp_key_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe readonly struct GetSha256FingerprintsResult
    {
        public readonly nint NumberOfFingerprints;
        public readonly sbyte** Fingerprints;
    }
}
