namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPrivateKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);

        // Assert
        privateKey.Base.ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Lock_Succeeds()
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);

        // Act
        using var lockedKey = privateKey.Lock(PgpSamples.Passphrase);

        // Assert
        var unlock = () => lockedKey.Unlock(PgpSamples.Passphrase);
        var lockAgain = () => privateKey.Lock(PgpSamples.Passphrase);

        lockedKey.Base.ForeignHandle.IsInvalid.Should().BeFalse();
        unlock.Should().NotThrow();
        lockAgain.Should().NotThrow();
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Export_Succeeds_WhenOutputingToStream(PgpEncoding encoding)
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Default);
        var exportedKeyStream = new MemoryStream();

        // Act
        privateKey.Export(exportedKeyStream, encoding);

        // Assert
        var exportedBytes = exportedKeyStream.ToArray();
        var importAction = () => PgpPrivateKey.Import(exportedBytes, encoding);
        var lockAfterImportAction = () => PgpPrivateKey.Import(exportedBytes, encoding).Lock(PgpSamples.Passphrase);

        importAction.Should().NotThrow();
        lockAfterImportAction.Should().NotThrow();
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Export_Succeeds_WhenOutputingToSpan(PgpEncoding encoding)
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Default);
        var outputBuffer = new byte[4096];

        // Act
        var length = privateKey.Export(outputBuffer, encoding);

        // Assert
        var exportedBytes = outputBuffer.AsMemory(..length);
        var importAction = () => PgpPrivateKey.Import(exportedBytes.Span, encoding);
        var lockAfterImportAction = () => PgpPrivateKey.Import(exportedBytes.Span, encoding).Lock(PgpSamples.Passphrase);

        importAction.Should().NotThrow();
        lockAfterImportAction.Should().NotThrow();
    }

    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var unlockedKey = PgpPrivateKey.ImportAndUnlock(PgpSamples.ArmoredLockedPrivateKey, PgpSamples.Passphrase, PgpEncoding.AsciiArmor);

        // Assert
        unlockedKey.Base.ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Version_ReturnsValidVersion()
    {
        // Act
        var version = PgpSamples.UnlockedPrivateKey.Version;

        // Assert
        version.Should().NotBe(0);
    }

    [Fact]
    public void Id_ReturnsValidId()
    {
        // Act
        var id = PgpSamples.UnlockedPrivateKey.Id;

        // Assert
        id.Should().NotBe(0);
    }

    [Fact]
    public void GetFingerprint_ReturnsFingerprint()
    {
        // Act
        var fingerprint = PgpSamples.UnlockedPrivateKey.GetFingerprint();

        // Assert
        fingerprint.Should().NotBeEmpty();
    }

    [Fact]
    public void GetSha256Fingerprints_ReturnsFingerprints()
    {
        // Act
        var fingerprints = PgpSamples.UnlockedPrivateKey.GetSha256Fingerprints();

        // Assert
        fingerprints.Should().NotBeEmpty();
    }

    [Fact]
    public void CanVerify_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.UnlockedPrivateKey.CanVerify;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void CanEncrypt_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.UnlockedPrivateKey.CanEncrypt;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void IsExpired_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.UnlockedPrivateKey.IsExpired;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void IsRevoked_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.UnlockedPrivateKey.IsRevoked;

        // Assert
        act.Should().NotThrow();
    }
}
