namespace Proton.Cryptography.Tests.Pgp;

internal static class PgpSamples
{
    private static readonly string DataDirPath = Path.Combine(AppContext.BaseDirectory, "data");

    public static readonly byte[] Passphrase = ReadPgpFile("passphrase.txt");
    public static readonly byte[] Password = ReadPgpFile("password.txt");

    public static readonly byte[] ArmoredLockedPrivateKey = ReadPgpFile("locked_private_key_v4.asc");
    public static readonly byte[] ArmoredLockedPrivateKeyV6 = ReadPgpFile("locked_private_key_v6.asc");
    public static readonly byte[] ArmoredPublicKey = ReadPgpFile("public_key_v4.asc");
    public static readonly byte[] ArmoredPublicKeyV6 = ReadPgpFile("public_key_v6.asc");
    public static readonly byte[] ArmoredEncryptedSignedMessage = ReadPgpFile("encrypted_message_signed.asc");
    public static readonly byte[] ArmoredEncryptedSignedMessageWithContext = ReadPgpFile("encrypted_message_signed_with_context.asc");
    public static readonly byte[] KeyBasedArmoredEncryptedUnsignedMessage = ReadPgpFile("encrypted_message_unsigned.asc");
    public static readonly byte[] KeyBasedArmoredEncryptedUnsignedAeadMessage = ReadPgpFile("encrypted_aead_message_unsigned.asc");
    public static readonly byte[] KeyBasedArmoredEncryptedMessageWithNonMatchingSignature = ReadPgpFile("encrypted_message_non_matching_signature.asc");
    public static readonly byte[] KeyBasedArmoredEncryptedMessageWithInvalidSignature = ReadPgpFile("encrypted_message_invalid_signature.asc");
    public static readonly byte[] PasswordBasedArmoredEncryptedUnsignedMessage = ReadPgpFile("encrypted_with_password_unsigned_message.asc");
    public static readonly byte[] ArmoredSignature = ReadPgpFile("signature.asc");
    public static readonly byte[] ArmoredInvalidSignature = ReadPgpFile("signature_invalid.asc");
    public static readonly byte[] ArmoredEncryptedSignature = ReadPgpFile("encrypted_signature.asc");

    public static readonly byte[] Signature = ReadPgpBase64File("signature_v4.b64");
    public static readonly byte[] InvalidSignature = ReadPgpBase64File("signature_v4_invalid.b64");
    public static readonly byte[] KeyPacket = ReadPgpBase64File("key_packet_v4.b64");
    public static readonly byte[] KeyPacketV6 = ReadPgpBase64File("key_packet_v6.b64");
    public static readonly byte[] DataPacket = ReadPgpBase64File("data_packet.b64");
    public static readonly byte[] SessionKeyToken = ReadPgpBase64File("session_key_token.b64");
    public static readonly byte[] LongDataPacket = ReadPgpBase64File("long_data_packet.b64");

    public static readonly byte[] ArmoredPlainSignedMessage = ReadPgpFile("plain_message_signed.asc");
    public static readonly byte[] ArmoredPlainSignedMessageWithContext = ReadPgpFile("plain_message_signed_with_context.asc");
    public static readonly byte[] ArmoredPlainMessageWithInvalidSignature = ReadPgpFile("plain_message_invalid_signature.asc");
    public static readonly byte[] ArmoredPlainMessageWithNonMatchingSignature = ReadPgpFile("plain_message_non_matching_signature.asc");
    public static readonly byte[] ArmoredPlainUnsignedMessage = ReadPgpFile("plain_message_unsigned.asc");

    public static readonly SymmetricCipher SessionKeyCipher = SymmetricCipher.Aes256;

    public static readonly PgpPrivateKey UnlockedPrivateKey = PgpPrivateKey.ImportAndUnlock(ArmoredLockedPrivateKey, Passphrase, PgpEncoding.AsciiArmor);
    public static readonly PgpPrivateKey UnlockedPrivateKeyV6 = PgpPrivateKey.ImportAndUnlock(ArmoredLockedPrivateKeyV6, Passphrase, PgpEncoding.AsciiArmor);

    public static readonly PgpPublicKey PublicKey = PgpPublicKey.Import(ArmoredPublicKey, PgpEncoding.AsciiArmor);
    public static readonly PgpPublicKey PublicKeyV6 = PgpPublicKey.Import(ArmoredPublicKeyV6, PgpEncoding.AsciiArmor);
    public static readonly PgpSessionKey SessionKey = PgpSessionKey.Import(SessionKeyToken, SessionKeyCipher);
    public static readonly PgpSessionKey SessionKeyV6 = PgpSessionKey.ImportForAead(SessionKeyToken, SessionKeyCipher);

    public static readonly byte[] PlainText = ReadPgpFile("plain_text.txt");
    public static readonly byte[] LongPlainText = ReadPgpFile("long_plain_text.txt");

    public static readonly string VerificationContext = Encoding.UTF8.GetString(ReadPgpFile("verification_context.txt")).Trim();

    private static byte[] ReadPgpFile(string name) =>
        File.ReadAllBytes(Path.Combine(DataDirPath, "pgp", name));

    private static byte[] ReadPgpBase64File(string name) =>
        Convert.FromBase64String(File.ReadAllText(Path.Combine(DataDirPath, "pgp", name)).Trim());
}
