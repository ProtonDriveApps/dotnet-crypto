using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents an OpenPGP key that can be used for encryption and verification operations.
/// </summary>
public readonly partial struct PgpKey : IVerificationKeyRingSource, IEncryptionKeyRingSource, IDisposable
{
    internal PgpKey(nint foreignHandle)
    {
        ForeignHandle = new ForeignKeySafeHandle(foreignHandle);
    }

    public nint Id => ForeignFunctions.GetId(ForeignHandle);
    public int Version => ForeignFunctions.GetVersion(ForeignHandle);
    public bool CanEncrypt => ForeignFunctions.GetCanEncrypt(ForeignHandle);
    public bool CanVerify => ForeignFunctions.GetCanVerify(ForeignHandle);
    public bool IsExpired => ForeignFunctions.GetIsExpired(ForeignHandle);
    public bool IsRevoked => ForeignFunctions.GetIsRevoked(ForeignHandle);

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    internal ForeignKeySafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public unsafe byte[] GetFingerprint()
    {
        ForeignFunctions.GetFingerprintBytes(ForeignHandle, out var fingerprintBytesPointer, out var fingerprintLength);

        if (fingerprintBytesPointer == null)
        {
            throw new PgpException("Could not get key fingerprint");
        }

        return InteropMemory.CopyToArrayAndFree<byte>(fingerprintBytesPointer, fingerprintLength);
    }

    public unsafe string[] GetSha256Fingerprints()
    {
        var interopResult = ForeignFunctions.GetSha256Fingerprints(ForeignHandle);

        var exception = default(Exception?);
        try
        {
            var result = new string[interopResult.FingerprintCount];
            for (var i = 0; i < interopResult.FingerprintCount; ++i)
            {
                var currentFingerprintPointer = *(interopResult.Fingerprints + i);
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
                    InteropMemory.Free(currentFingerprintPointer);
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
            InteropMemory.Free(interopResult.Fingerprints);
        }
    }

    public void Export(Stream stream, PgpEncoding encoding)
    {
        var streamHandle = GCHandle.Alloc(stream);

        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(streamHandle);

            using var error = ForeignFunctions.Export(ForeignHandle, forcePublic: false, encoding == PgpEncoding.AsciiArmor, outputWriter);
            error.ThrowPgpExceptionIfAny();
        }
        finally
        {
            streamHandle.Free();
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

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe readonly struct InteropSha256FingerprintsResult
    {
        public readonly nint FingerprintCount;
        public readonly sbyte** Fingerprints;
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_export")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Export(
            ForeignKeySafeHandle keyHandle,
            [MarshalAs(UnmanagedType.U1)] bool forcePublic,
            [MarshalAs(UnmanagedType.U1)] bool armored,
            InteropWriter outputWriter);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_get_version")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial int GetVersion(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_get_key_id")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial nint GetId(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_get_fingerprint_bytes")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial void GetFingerprintBytes(ForeignKeySafeHandle keyHandle, out byte* fingerprintBytes, out nuint fingerprintLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_get_sha256_fingerprints")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropSha256FingerprintsResult GetSha256Fingerprints(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_can_verify")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.U1)]
        public static partial bool GetCanEncrypt(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_can_verify")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.U1)]
        public static partial bool GetCanVerify(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_is_expired")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.U1)]
        public static partial bool GetIsExpired(ForeignKeySafeHandle keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_is_revoked")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.U1)]
        public static partial bool GetIsRevoked(ForeignKeySafeHandle keyHandle);
    }
}
