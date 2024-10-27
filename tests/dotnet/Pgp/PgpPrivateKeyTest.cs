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
        // Act
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);
        using var lockedPrivateKey = privateKey.Lock(PgpSamples.Passphrase);

        // Assert
        lockedPrivateKey.GoKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var privateKey = default(PgpPrivateKey);

        // Act
        var act = privateKey.Export;

        // Assert
        act.Invoking(x => x.Invoke(Stream.Null, default)).Should().Throw<Exception>();
    }

    [Fact]
    public void Version_ReturnsValidVersion()
    {
        // Act
        var version = PgpSamples.PrivateKey.Version;

        // Assert
        version.Should().NotBe(default);
    }

    [Fact]
    public void Id_ReturnsValidId()
    {
        // Act
        var id = PgpSamples.PrivateKey.Id;

        // Assert
        id.Should().NotBe(default);
    }

    [Fact]
    public void GetFingerprint_ReturnsFingerprint()
    {
        // Act
        var fingerprint = PgpSamples.PrivateKey.GetFingerprint();

        // Assert
        fingerprint.Should().NotBeEmpty();
    }

    [Fact]
    public void GetSha256Fingerprints_ReturnsFingerprints()
    {
        // Act
        var fingerprints = PgpSamples.PrivateKey.GetSha256Fingerprints();

        // Assert
        fingerprints.Should().NotBeEmpty();
    }

    [Fact]
    public void CanVerify_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.CanVerify;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void CanEncrypt_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.CanEncrypt;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void IsExpired_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.IsExpired;

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void IsRevoked_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.IsRevoked;

        // Assert
        act.Should().NotThrow();
    }
}
