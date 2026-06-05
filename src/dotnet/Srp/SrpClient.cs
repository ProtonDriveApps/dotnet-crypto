using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Srp;

public readonly partial struct SrpClient : IDisposable
{
    private SrpClient(string username, nint foreignHandle)
    {
        Username = username;
        ForeignHandle = new ForeignSrpAuthSafeHandle(foreignHandle);
    }

    public string Username { get; }

    private ForeignSrpAuthSafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public static SrpClient Create(string username, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, string signedModulus)
    {
        return Create(username, password, salt, signedModulus, GetDefaultModulusVerificationKey());
    }

    public static unsafe SrpClient Create(
        string username,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        string signedModulus,
        PgpPublicKey verificationKey)
    {
        var usernameUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(username.Length);
        var usernameUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(
            usernameUtf8BytesMaxLength,
            out var usernameHeapMemory,
            out var usernameHeapMemoryOwner)
            ? usernameHeapMemory.Span
            : stackalloc byte[usernameUtf8BytesMaxLength];

        using (usernameHeapMemoryOwner)
        {
            var signedModulusUtf8BytesMaxLength = Encoding.UTF8.GetMaxByteCount(signedModulus.Length);
            var signedModulusUtf8Bytes = MemoryProvider.GetHeapMemoryIfTooLargeForStack(
                signedModulusUtf8BytesMaxLength,
                out var signedModulusHeapMemory,
                out var signedModulusHeapMemoryOwner)
                ? signedModulusHeapMemory.Span
                : stackalloc byte[signedModulusUtf8BytesMaxLength];

            using (signedModulusHeapMemoryOwner)
            {
                var usernameUtf8BytesLength = Encoding.UTF8.GetBytes(username, usernameUtf8Bytes);
                var signedModulusUtf8BytesLength = Encoding.UTF8.GetBytes(signedModulus, signedModulusUtf8Bytes);

                fixed (byte* usernameUtf8BytesPointer = usernameUtf8Bytes)
                {
                    fixed (byte* passwordPointer = password)
                    {
                        fixed (byte* saltPointer = salt)
                        {
                            fixed (byte* signedModulusUtf8BytesPointer = signedModulusUtf8Bytes)
                            {
                                var parameters = new InteropSrpAuthCreationParameters(
                                    usernameUtf8BytesPointer,
                                    (nuint)usernameUtf8BytesLength,
                                    passwordPointer,
                                    (nuint)password.Length,
                                    saltPointer,
                                    (nuint)salt.Length,
                                    signedModulusUtf8BytesPointer,
                                    (nuint)signedModulusUtf8BytesLength);

                                using var error = ForeignFunctions.Create(parameters, verificationKey.Base.ForeignHandle, out var srpAuthHandle);
                                error.ThrowSrpExceptionIfAny();

                                return new SrpClient(username, srpAuthHandle);
                            }
                        }
                    }
                }
            }
        }
    }

    public static byte[] HashPassword(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        var digest = new byte[60];

        using var error = ForeignFunctions.HashPassword(
            MemoryMarshal.GetReference(password),
            (nuint)password.Length,
            MemoryMarshal.GetReference(salt),
            (nuint)salt.Length,
            digest[0],
            (nuint)digest.Length);

        error.ThrowSrpExceptionIfAny();

        return digest;
    }

    public static PgpPublicKey GetDefaultModulusVerificationKey()
    {
        using var error = ForeignFunctions.GetModulusVerificationKey(out var keyHandle);
        error.ThrowSrpExceptionIfAny();

        return new PgpPublicKey(keyHandle);
    }

    public byte[] DeriveVerifier(int bitLength)
    {
        var verifier = new byte[bitLength / 8];

        using var error = ForeignFunctions.DeriveVerifier(ForeignHandle, MemoryMarshal.GetArrayDataReference(verifier), (nuint)verifier.Length, bitLength);
        error.ThrowSrpExceptionIfAny();

        return verifier;
    }

    public unsafe SrpClientHandshake ComputeHandshake(ReadOnlySpan<byte> serverEphemeral, int bitLength)
    {
        var bufferSize = bitLength / 8;

        var clientProof = new byte[bufferSize];
        var clientEphemeral = new byte[bufferSize];

        fixed (byte* clientProofBufferPointer = clientProof)
        {
            fixed (byte* clientEphemeralBufferPointer = clientEphemeral)
            {
                var clientResponseBuffers = new InteropClientResponseBuffers(
                    clientProofBufferPointer,
                    (nuint)bufferSize,
                    clientEphemeralBufferPointer,
                    (nuint)bufferSize);

                using var error = ForeignFunctions.ComputeHandshake(
                    ForeignHandle,
                    MemoryMarshal.GetReference(serverEphemeral),
                    (nuint)serverEphemeral.Length,
                    clientResponseBuffers,
                    bitLength,
                    out var clientHandshakeHandle);

                error.ThrowSrpExceptionIfAny();

                return new SrpClientHandshake(clientHandshakeHandle, clientProof, clientEphemeral);
            }
        }
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe readonly struct InteropSrpAuthCreationParameters(
        byte* username,
        nuint usernameLength,
        byte* password,
        nuint passwordLength,
        byte* salt,
        nuint saltLength,
        byte* signedModulus,
        nuint signedModulusLength)
    {
        public readonly nuint UsernameLength = usernameLength;
        public readonly nuint PasswordLength = passwordLength;
        public readonly nuint SaltLength = saltLength;
        public readonly nuint SignedModulusLength = signedModulusLength;
        public readonly byte* Username = username;
        public readonly byte* Password = password;
        public readonly byte* Salt = salt;
        public readonly byte* SignedModulus = signedModulus;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe readonly struct InteropClientResponseBuffers(byte* proofBuffer, nuint proofBufferLength, byte* ephemeralBuffer, nuint ephemeralBufferLength)
    {
        public readonly nuint ProofBufferLength = proofBufferLength;
        public readonly nuint EphemeralBufferLength = ephemeralBufferLength;
        public readonly byte* ProofBuffer = proofBuffer;
        public readonly byte* EphemeralBuffer = ephemeralBuffer;
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_auth_create")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Create(in InteropSrpAuthCreationParameters parameters, ForeignKeySafeHandle keyHandle, out nint clientHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_auth_derive_verifier")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError DeriveVerifier(
            ForeignSrpAuthSafeHandle srpAuthHandle,
            in byte verifierBuffer,
            nuint verifierBufferLength,
            int bitLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_client_handshake_compute")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError ComputeHandshake(
            ForeignSrpAuthSafeHandle srpAuthHandle,
            in byte serverEphemeral,
            nuint serverEphemeralLength,
            in InteropClientResponseBuffers clientResponseBuffers,
            int bitLength,
            out nint clientHandshakeHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_get_modulus_verification_key")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError GetModulusVerificationKey(out nint keyHandle);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "hash_password")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static unsafe partial InteropError HashPassword(
            in byte password,
            nuint passwordLength,
            in byte salt,
            nuint saltLength,
            in byte digestBuffer,
            nuint digestBufferLength);

        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "srp_auth_destroy")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial void ReleaseHandle(nint handle);
    }

    private sealed class ForeignSrpAuthSafeHandle() : SafeHandleZeroIsInvalid(ownsHandle: true)
    {
        public ForeignSrpAuthSafeHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            ForeignFunctions.ReleaseHandle(handle);

            return true;
        }
    }
}
