namespace Proton.Cryptography.Tests.Pgp;

internal static class PgpEncodingAssertions
{
    private static readonly byte[] ArmorPrefix = "-----BEGIN"u8.ToArray();

    internal static void ShouldMatchEncoding(MemoryStream output, PgpEncoding encoding) =>
        ShouldMatchEncoding(output.GetSegment(), encoding);

    internal static void ShouldMatchEncoding(ArraySegment<byte> output, PgpEncoding encoding)
    {
        switch (encoding)
        {
            case PgpEncoding.AsciiArmor:
                output.Should().StartWith(ArmorPrefix);
                break;
            case PgpEncoding.None:
                output.AsSpan().StartsWith(ArmorPrefix).Should().BeFalse();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(encoding), encoding, null);
        }
    }
}
