namespace Proton.Cryptography.Pgp;

public static class PgpEnvironment
{
    public static TimeProvider? DefaultTimeProviderOverride { get; set; }
    public static long DefaultAeadStreamingChunkLength { get; set; } = 0;
}
