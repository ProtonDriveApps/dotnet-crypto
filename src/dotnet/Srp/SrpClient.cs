using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp;
using Proton.Cryptography.Srp.Interop;

namespace Proton.Cryptography.Srp;

public readonly partial struct SrpClient : IDisposable
{
    private readonly GoSrpAuth? _goSrpAuth;

    private SrpClient(string username, GoSrpAuth goSrpAuth)
    {
        Username = username;
        _goSrpAuth = goSrpAuth;
    }

    public string Username { get; }

    private GoSrpAuth GoSrpAuth => _goSrpAuth ?? throw new InvalidOperationException("Invalid handle");

    public static SrpClient Create(string username, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, string signedModulus)
    {
        return Create(username, password, salt, signedModulus, GetDefaultModulusVerificationKey());
    }

    public static SrpClient Create(string username, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, string signedModulus, PgpPublicKey verificationKey)
    {
        var goSrpAuth = GoSrpAuth.Create(username, password, salt, signedModulus, verificationKey);

        return new SrpClient(username, goSrpAuth);
    }

    public static byte[] HashPassword(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        var digest = new byte[60];

        using var goError = GoHashPassword(
            MemoryMarshal.GetReference(password),
            (nuint)password.Length,
            MemoryMarshal.GetReference(salt),
            (nuint)salt.Length,
            digest[0],
            (nuint)digest.Length);

        goError.ThrowIfFailure();

        return digest;
    }

    public static PgpPublicKey GetDefaultModulusVerificationKey()
    {
        using var goError = GoGetModulusVerificationKey(out var unsafeKeyHandle);
        goError.ThrowIfFailure();

        return PgpPublicKey.FromUnsafeHandle(unsafeKeyHandle);
    }

    public byte[] DeriveVerifier(int bitLength)
    {
        return GoSrpAuth.DeriveVerifier(bitLength);
    }

    public SrpClientHandshake ComputeHandshake(ReadOnlySpan<byte> serverEphemeral, int bitLength)
    {
        var bufferSize = bitLength / 8;

        var clientProof = new byte[bufferSize];
        var clientEphemeral = new byte[bufferSize];

        var unsafeGoClientHandshakeHandle = GoSrpAuth.ComputeHandshake(serverEphemeral, clientProof, clientEphemeral, bitLength);

        return new SrpClientHandshake(unsafeGoClientHandshakeHandle, clientProof, clientEphemeral);
    }

    public void Dispose()
    {
        _goSrpAuth?.Dispose();
    }

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "srp_get_modulus_verification_key")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoGetModulusVerificationKey(out nint keyHandle);

    [LibraryImport(Constants.GoLibraryName, EntryPoint = "hash_password")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe partial GoError GoHashPassword(
        in byte password,
        nuint passwordLength,
        in byte salt,
        nuint saltLength,
        in byte digestBuffer,
        nuint digestBufferLength);
}
