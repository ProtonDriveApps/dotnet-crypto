namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct InteropSigningParameters
{
    public readonly byte Profile;
    public readonly nuint SigningKeysLength;
    public readonly bool HasSigningContext;
    public readonly bool HasSigningTime;
    public readonly bool Utf8;
    public readonly void* SigningKeys;
    public readonly nint SigningContext = 0;
    public readonly ulong SigningTime;

    public InteropSigningParameters(void* signingKeys, nuint signingKeysLength, PgpProfile profile, TimeProvider? timeProviderOverride)
    {
        Profile = (byte)profile;
        SigningKeysLength = signingKeysLength;
        SigningKeys = signingKeys;

        var timeProvider = timeProviderOverride ?? PgpConfiguration.DefaultTimeProviderOverride;

        if (timeProvider is not null)
        {
            HasSigningTime = true;
            SigningTime = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        }
    }
}
