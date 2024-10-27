namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct GoSigningParameters(void* signingKeys, nuint signingKeysLength)
{
    public readonly nuint SigningKeysLength = signingKeysLength;
    public readonly bool HasSigningContext = default;
    public readonly bool HasSignTime = true;
    public readonly bool Utf8 = default;
    public readonly void* SigningKeys = signingKeys;
    public readonly nint SigningContext = default;
    public readonly long SignTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}
