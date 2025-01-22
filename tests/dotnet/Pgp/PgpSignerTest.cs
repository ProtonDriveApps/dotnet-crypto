using Microsoft.Extensions.Time.Testing;

namespace Proton.Cryptography.Tests.Pgp;

public class PgpSignerTest
{
    [Fact]
    public void Sign_OutputsSignatureOnly()
    {
        // Act
        var signatureBytes = PgpSigner.Sign(Encoding.ASCII.GetBytes(PgpSamples.PlainText), PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        var signature = Encoding.ASCII.GetString(signatureBytes);
        signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");
        signature.Should().EndWith("-----END PGP SIGNATURE-----");
    }

    [Fact]
    public void Sign_OutputsFullMessage()
    {
        // Act
        var messageBytes = PgpSigner.Sign(
            Encoding.ASCII.GetBytes(PgpSamples.PlainText),
            PgpSamples.PrivateKey,
            PgpEncoding.AsciiArmor,
            SigningOutputType.FullMessage);

        // Assert
        var message = Encoding.ASCII.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        message.Should().EndWith("-----END PGP MESSAGE-----");
    }

    [Fact]
    public void SignCleartext_Succeeds()
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var messageReader = new StreamReader(outputStream);

        // Act
        PgpSigner.SignCleartext(Encoding.ASCII.GetBytes(PgpSamples.PlainText), PgpSamples.PrivateKey, outputStream);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();
        message.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");
        message.Should().EndWith("-----END PGP SIGNATURE-----");
    }

    [Fact]
    public void Sign_Fails_WithInvalidTime()
    {
        // Arrange
        var keyGenerationTimeProvider = new FakeTimeProvider(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var encryptionTimeProvider = new FakeTimeProvider(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var privateKey = PgpPrivateKey.Generate("test", "test@example.com", KeyGenerationAlgorithm.Default, keyGenerationTimeProvider);

        // Act
        var act = () => privateKey.Sign(Encoding.UTF8.GetBytes(PgpSamples.PlainText), timeProviderOverride: encryptionTimeProvider);

        // Assert
        act.Should().Throw<PgpException>().Where(exception => exception.Message.Contains("no valid signing keys"));
    }
}
