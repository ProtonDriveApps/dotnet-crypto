using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

internal static class PgpEncodingExtensions
{
    public static GoPgpEncoding ToGoEncoding(this PgpEncoding encoding)
    {
        return ToGoEncoding((PgpEncoding?)encoding);
    }

    public static GoPgpEncoding ToGoEncoding(this PgpEncoding? encoding)
    {
        return encoding switch
        {
            PgpEncoding.None => GoPgpEncoding.Bytes,
            PgpEncoding.AsciiArmor => GoPgpEncoding.Armor,
            _ => GoPgpEncoding.Auto
        };
    }
}
