namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpSecretKeyTest
{
    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var importedKey = PgpSecretKey.Import(PgpSamples.ArmoredLockedPrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        importedKey.GoKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Unlock_Succeeds()
    {
        // Arrange
        using var secretKey = PgpSecretKey.Import(PgpSamples.ArmoredLockedPrivateKey, PgpEncoding.AsciiArmor);

        // Act
        using var unlockedKey = secretKey.Unlock(PgpSamples.Passphrase);

        // Assert
        unlockedKey.GoKey.IsInvalid.Should().BeFalse();
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
