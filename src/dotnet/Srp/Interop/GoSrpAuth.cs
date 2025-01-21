using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Srp.Interop;

internal sealed partial class GoSrpAuth() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    private GoSrpAuth(nint handle)
        : this()
    {
        SetHandle(handle);
    }

    public static unsafe GoSrpAuth Create(
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
                                var parameters = new GoSrpAuthCreationParameters(
                                    usernameUtf8BytesPointer,
                                    (nuint)usernameUtf8BytesLength,
                                    passwordPointer,
                                    (nuint)password.Length,
                                    saltPointer,
                                    (nuint)salt.Length,
                                    signedModulusUtf8BytesPointer,
                                    (nuint)signedModulusUtf8BytesLength);

                                using var goError = GoCreate(parameters, verificationKey.GoKey, out var unsafeGoSrpAuthHandle);
                                goError.ThrowIfFailure();

                                return new GoSrpAuth(unsafeGoSrpAuthHandle);
                            }
                        }
                    }
                }
            }
        }
    }

    public byte[] DeriveVerifier(int bitLength)
    {
        var verifier = new byte[bitLength / 8];

        using var goError = GoDeriveVerifier(this, MemoryMarshal.GetArrayDataReference(verifier), (nuint)verifier.Length, bitLength);
        goError.ThrowIfFailure();

        return verifier;
    }

    public unsafe nint ComputeHandshake(ReadOnlySpan<byte> serverEphemeral, byte[] clientProofBuffer, byte[] clientEphemeralBuffer, int bitLength)
    {
        var bufferSize = bitLength / 8;

        fixed (byte* clientProofBufferPointer = clientProofBuffer)
        {
            fixed (byte* clientEphemeralBufferPointer = clientEphemeralBuffer)
            {
                var clientResponseBuffers = new GoClientResponseBuffers(
                    clientProofBufferPointer,
                    (nuint)bufferSize,
                    clientEphemeralBufferPointer,
                    (nuint)bufferSize);

                using var goError = GoComputeHandshake(
                    this,
                    MemoryMarshal.GetReference(serverEphemeral),
                    (nuint)serverEphemeral.Length,
                    clientResponseBuffers,
                    bitLength,
                    out var goClientHandshakeHandle);

                goError.ThrowIfFailure();

                return goClientHandshakeHandle;
            }
        }
    }

    protected override bool ReleaseHandle()
    {
        GoReleaseHandle(handle);

        return true;
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_auth_create")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial GoError GoCreate(in GoSrpAuthCreationParameters parameters, GoKey goKey, out nint clientHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_auth_derive_verifier")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoDeriveVerifier(GoSrpAuth goAuth, in byte verifierBuffer, nuint verifierBufferLength, int bitLength);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_client_handshake_compute")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoComputeHandshake(
        GoSrpAuth goAuth,
        in byte serverEphemeral,
        nuint serverEphemeralLength,
        in GoClientResponseBuffers clientResponseBuffers,
        int bitLength,
        out nint clientHandshakeHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_auth_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial void GoReleaseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe readonly struct GoSrpAuthCreationParameters(
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
    private unsafe readonly struct GoClientResponseBuffers(byte* proofBuffer, nuint proofBufferLength, byte* ephemeralBuffer, nuint ephemeralBufferLength)
    {
        public readonly nuint ProofBufferLength = proofBufferLength;
        public readonly nuint EphemeralBufferLength = ephemeralBufferLength;
        public readonly byte* ProofBuffer = proofBuffer;
        public readonly byte* EphemeralBuffer = ephemeralBuffer;
    }
}
