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
        signature.ShouldStartWith("-----BEGIN PGP SIGNATURE-----");
        signature.ShouldEndWith("-----END PGP SIGNATURE-----");
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
        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
        message.ShouldEndWith("-----END PGP MESSAGE-----");
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
        message.ShouldStartWith("-----BEGIN PGP SIGNED MESSAGE-----");
        message.ShouldEndWith("-----END PGP SIGNATURE-----");
    }

    [Theory]
    [InlineData(2000, 1000)]
    [InlineData(3000, null)]
    [InlineData(null, 2000)]
    public void Sign_Fails_WithInvalidTime(int? keyGenerationTimeOverrideYear, int? encryptionTimeOverrideYear)
    {
        // Arrange
        var keyGenerationTimeProvider = keyGenerationTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(keyGenerationTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var encryptionTimeProvider = encryptionTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(encryptionTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var privateKey = PgpPrivateKey.Generate("test", "test@example.com", KeyGenerationAlgorithm.Default, keyGenerationTimeProvider);

        // Act
        var act = new Action(() => privateKey.Sign(Encoding.UTF8.GetBytes(PgpSamples.PlainText), timeProviderOverride: encryptionTimeProvider));

        // Assert
        act.ShouldThrow<PgpException>().Message.ShouldContain("no valid signing keys");
    }

    [Theory]
    [InlineData(1000, 2000)]
    [InlineData(2000, null)]
    [InlineData(null, 3000)]
    public void Sign_Succeeds_WithValidTime(int? keyGenerationTimeOverrideYear, int? encryptionTimeOverrideYear)
    {
        // Arrange
        var keyGenerationTimeProvider = keyGenerationTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(keyGenerationTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var encryptionTimeProvider = encryptionTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(encryptionTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var privateKey = PgpPrivateKey.Generate("test", "test@example.com", KeyGenerationAlgorithm.Default, keyGenerationTimeProvider);

        // Act
        var act = () => privateKey.Sign(Encoding.UTF8.GetBytes(PgpSamples.PlainText), timeProviderOverride: encryptionTimeProvider);

        // Assert
        act.ShouldNotThrow();
    }
}
