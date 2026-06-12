using Microsoft.Extensions.Time.Testing;

namespace Proton.Cryptography.Tests.Pgp;

public class PgpSignerTest
{
    [Fact]
    public void Sign_OutputsSignatureOnly()
    {
        // Act
        var signatureBytes = PgpSigner.Sign(PgpSamples.PlainText, PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        signatureBytes.Should().StartWith(PgpArmorHeaders.Signature);

        var decode = () => PgpArmorDecoder.Decode(signatureBytes);
        decode.Should().NotThrow();
    }

    [Fact]
    public void Sign_OutputsFullMessage()
    {
        // Act
        var messageBytes = PgpSigner.Sign(
            PgpSamples.PlainText,
            PgpSamples.UnlockedPrivateKey,
            PgpEncoding.AsciiArmor,
            SigningOutputType.FullMessage);

        // Assert
        messageBytes.Should().StartWith(PgpArmorHeaders.Message);

        var decode = () => PgpArmorDecoder.Decode(messageBytes);
        decode.Should().NotThrow();
    }

    [Fact]
    public void SignCleartext_Succeeds()
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var messageReader = new StreamReader(outputStream);

        // Act
        PgpSigner.SignCleartext(PgpSamples.PlainText, PgpSamples.UnlockedPrivateKey, outputStream);

        // Assert
        var messageBytes = outputStream.ToArray();
        messageBytes.Should().StartWith(PgpArmorHeaders.SignedMessage);
    }

    [Theory]
    [InlineData(2000, 1970)]
    [InlineData(2100, null)]
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

        var privateKey = PgpPrivateKey.Generate("test", "test@example.com", KeyGenerationAlgorithm.Default, timeProviderOverride: keyGenerationTimeProvider);

        // Act
        var act = new Action(() => privateKey.Sign(PgpSamples.PlainText, timeProviderOverride: encryptionTimeProvider));

        // Assert
        act.Should().Throw<PgpException>().And.Message.Should().Contain("no valid signing keys");
    }

    [Theory]
    [InlineData(1970, 2000)]
    [InlineData(2000, null)]
    [InlineData(null, 2100)]
    public void Sign_Succeeds_WithValidTime(int? keyGenerationTimeOverrideYear, int? encryptionTimeOverrideYear)
    {
        // Arrange
        var keyGenerationTimeProvider = keyGenerationTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(keyGenerationTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var encryptionTimeProvider = encryptionTimeOverrideYear is not null
            ? new FakeTimeProvider(new DateTimeOffset(encryptionTimeOverrideYear.Value, 1, 1, 0, 0, 0, TimeSpan.Zero))
            : TimeProvider.System;

        var privateKey = PgpPrivateKey.Generate("test", "test@example.com", KeyGenerationAlgorithm.Default, timeProviderOverride: keyGenerationTimeProvider);

        // Act
        var act = () => privateKey.Sign(PgpSamples.PlainText, timeProviderOverride: encryptionTimeProvider);

        // Assert
        act.Should().NotThrow();
    }
}
