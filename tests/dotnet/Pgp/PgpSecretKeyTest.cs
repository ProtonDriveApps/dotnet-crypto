namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpSecretKeyTest
{
    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Export_Succeeds(PgpEncoding encoding)
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Default);
        var secretKey = privateKey.Lock(PgpSamples.Passphrase);
        var exportedKeyStream = new MemoryStream();

        // Act
        secretKey.Export(exportedKeyStream, encoding);

        // Assert
        var exportedBytes = exportedKeyStream.ToArray();
        var importAction = () => PgpSecretKey.Import(exportedBytes, encoding);
        var unlockAfterImportAction = () => PgpSecretKey.Import(exportedBytes, encoding).Unlock(PgpSamples.Passphrase);

        importAction.Should().NotThrow();
        unlockAfterImportAction.Should().NotThrow();
    }

    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var importedKey = PgpSecretKey.Import(PgpSamples.ArmoredLockedPrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        importedKey.Base.ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Unlock_Succeeds()
    {
        // Arrange
        using var secretKey = PgpSecretKey.Import(PgpSamples.ArmoredLockedPrivateKey, PgpEncoding.AsciiArmor);

        // Act
        using var unlockedKey = secretKey.Unlock(PgpSamples.Passphrase);

        // Assert
        unlockedKey.Base.ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var secretKey = default(PgpSecretKey);

        // Act
        var act = new Action(() => secretKey.Export(Stream.Null, default));

        // Assert
        act.Should().Throw<Exception>();
    }
}
