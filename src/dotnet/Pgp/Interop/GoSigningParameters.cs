namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct GoSigningParameters
{
    public readonly nuint SigningKeysLength;
    public readonly bool HasSigningContext;
    public readonly bool HasSigningTime;
    public readonly bool Utf8;
    public readonly void* SigningKeys;
    public readonly nint SigningContext = 0;
    public readonly long SigningTime;

    public GoSigningParameters(void* signingKeys, nuint signingKeysLength, TimeProvider? timeProviderOverride)
    {
        SigningKeysLength = signingKeysLength;
        SigningKeys = signingKeys;

        var timeProvider = timeProviderOverride ?? PgpEnvironment.DefaultTimeProviderOverride;

        if (timeProvider is not null)
        {
            HasSigningTime = true;
            SigningTime = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        }
    }
}
