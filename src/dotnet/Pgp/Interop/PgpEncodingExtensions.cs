namespace Proton.Cryptography.Pgp.Interop;

internal static class PgpEncodingExtensions
{
    extension(PgpEncoding encoding)
    {
        public InteropPgpEncoding ToInteropEncoding()
        {
            return ((PgpEncoding?)encoding).ToInteropEncoding();
        }
    }

    extension(PgpEncoding? encoding)
    {
        public InteropPgpEncoding ToInteropEncoding()
        {
            return encoding switch
            {
                PgpEncoding.None => InteropPgpEncoding.Bytes,
                PgpEncoding.AsciiArmor => InteropPgpEncoding.Armor,
                _ => InteropPgpEncoding.Auto,
            };
        }
    }
}
