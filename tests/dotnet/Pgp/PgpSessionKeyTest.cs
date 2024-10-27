namespace Proton.Cryptography.Tests.Pgp;

public class PgpSessionKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Generate(SymmetricCipher.Aes256);

        // Assert
        sessionKey.GoSessionKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Assert
        sessionKey.GoSessionKey.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Export_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var (token, cipher) = sessionKey.Export();

        // Assert
        token.Should().Equal(PgpSamples.SessionKeyToken);
        cipher.Should().Be(PgpSamples.SessionKeyCipher);
    }

    [Fact]
    public void EncryptToStream_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var outputStream = new MemoryStream();

        // Act
        sessionKey.ToKeyPackets(PgpSamples.PublicKey, outputStream);

        // Assert
        outputStream.Length.Should().Be(PgpSamples.KeyPacket.Length);
    }

    [Fact]
    public void ToKeyPacket_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var keyPacketOutputStream = new MemoryStream();

        // Act
        sessionKey.ToKeyPackets(PgpSamples.PublicKey, keyPacketOutputStream);

        // Assert
        keyPacketOutputStream.ToArray().Should().HaveCount(PgpSamples.KeyPacket.Length);
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var sessionKey = default(PgpSessionKey);

        // Act
        var act = sessionKey.Export;

        // Assert
        act.Should().Throw<Exception>();
    }
}
