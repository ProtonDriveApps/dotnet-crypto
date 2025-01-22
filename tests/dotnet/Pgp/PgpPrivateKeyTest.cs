namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPrivateKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);

        // Assert
        privateKey.GoKey.IsInvalid.ShouldBeFalse();
    }

    [Fact]
    public void Lock_Succeeds()
    {
        // Act
        using var privateKey = PgpPrivateKey.Generate("Test", "test@example.com", KeyGenerationAlgorithm.Ecc);
        using var lockedPrivateKey = privateKey.Lock(PgpSamples.Passphrase);

        // Assert
        lockedPrivateKey.GoKey.IsInvalid.ShouldBeFalse();
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var privateKey = default(PgpPrivateKey);

        // Act
        var act = new Action(() => privateKey.Export(Stream.Null, default));

        // Assert
        act.ShouldThrow<Exception>();
    }

    [Fact]
    public void Version_ReturnsValidVersion()
    {
        // Act
        var version = PgpSamples.PrivateKey.Version;

        // Assert
        version.ShouldNotBe(0);
    }

    [Fact]
    public void Id_ReturnsValidId()
    {
        // Act
        var id = PgpSamples.PrivateKey.Id;

        // Assert
        id.ShouldNotBe(0);
    }

    [Fact]
    public void GetFingerprint_ReturnsFingerprint()
    {
        // Act
        var fingerprint = PgpSamples.PrivateKey.GetFingerprint();

        // Assert
        fingerprint.ShouldNotBeEmpty();
    }

    [Fact]
    public void GetSha256Fingerprints_ReturnsFingerprints()
    {
        // Act
        var fingerprints = PgpSamples.PrivateKey.GetSha256Fingerprints();

        // Assert
        fingerprints.ShouldNotBeEmpty();
    }

    [Fact]
    public void CanVerify_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.CanVerify;

        // Assert
        act.ShouldNotThrow();
    }

    [Fact]
    public void CanEncrypt_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.CanEncrypt;

        // Assert
        act.ShouldNotThrow();
    }

    [Fact]
    public void IsExpired_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.IsExpired;

        // Assert
        act.ShouldNotThrow();
    }

    [Fact]
    public void IsRevoked_DoesNotThrow()
    {
        // Act
        var act = () => PgpSamples.PrivateKey.IsRevoked;

        // Assert
        act.ShouldNotThrow();
    }
}
