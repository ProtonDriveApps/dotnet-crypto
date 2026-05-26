namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPrivateKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);

        // Assert
        privateKey.GoKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Lock_Succeeds()
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);

        // Act
        using var lockedKey = privateKey.Lock(PgpSamples.Passphrase);

        // Assert
        lockedKey.GoKey.IsInvalid.Should().BeFalse();
        var unlock = () => lockedKey.Unlock(PgpSamples.Passphrase);
        unlock.Should().NotThrow();
    }

    [Fact]
    public void Unlock_Succeeds()
    {
        // Arrange
        using var privateKey = PgpPrivateKey.Import(PgpSamples.ArmoredLockedPrivateKey, PgpEncoding.AsciiArmor);

        // Act
        using var unlockedKey = privateKey.Unlock(PgpSamples.Passphrase);

        // Assert
        unlockedKey.GoKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void ImportAndUnlock_Succeeds()
    {
        // Act
        using var unlockedKey = PgpPrivateKey.ImportAndUnlock(PgpSamples.ArmoredLockedPrivateKey, PgpSamples.Passphrase, PgpEncoding.AsciiArmor);

        // Assert
        unlockedKey.GoKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var privateKey = default(PgpPrivateKey);

        // Act
        var act = new Action(() => privateKey.Export(Stream.Null, default));

        // Assert
        act.Should().Throw<Exception>();
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
