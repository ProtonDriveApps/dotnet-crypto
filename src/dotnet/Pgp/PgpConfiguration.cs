namespace Proton.Cryptography.Pgp;

public static class PgpConfiguration
{
    // This allowance includes a lot of headroom for peace of mind
    private const int PgpOverheadAllowance = 1 << 12;

    public static TimeProvider? DefaultTimeProviderOverride { get; set; }
    public static int DefaultAeadStreamingChunkLength { get; set; }

    /// <summary>
    /// Gets the minimum input length for AEAD decryption.
    /// </summary>
    public static int GetAeadDecryptionMinimumInputLength(int aeadChunkLength) => aeadChunkLength + PgpOverheadAllowance;
}
