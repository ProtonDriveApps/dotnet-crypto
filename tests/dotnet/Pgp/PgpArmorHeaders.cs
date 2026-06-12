namespace Proton.Cryptography.Tests.Pgp;

internal static class PgpArmorHeaders
{
    public static readonly byte[] Signature = "-----BEGIN PGP SIGNATURE-----"u8.ToArray();
    public static readonly byte[] Message = "-----BEGIN PGP MESSAGE-----"u8.ToArray();
    public static readonly byte[] SignedMessage = "-----BEGIN PGP SIGNED MESSAGE-----"u8.ToArray();
}
