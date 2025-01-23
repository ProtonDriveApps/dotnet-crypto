namespace Proton.Cryptography.Tests.Pgp;

public class PgpSessionKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Generate(PgpSamples.SessionKeyCipher);

        // Assert
        sessionKey.GoSessionKey.IsInvalid.ShouldBeFalse();
    }

    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Assert
        sessionKey.GoSessionKey.IsInvalid.ShouldBeFalse();
    }

    [Fact]
    public void Export_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var (token, cipher) = sessionKey.Export();

        // Assert
        token.ShouldBe(PgpSamples.SessionKeyToken);
        cipher.ShouldBe(PgpSamples.SessionKeyCipher);
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
        outputStream.Length.ShouldBe(PgpSamples.KeyPacket.Length);
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
        keyPacketOutputStream.ToArray().Length.ShouldBe(PgpSamples.KeyPacket.Length);
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var sessionKey = default(PgpSessionKey);

        // Act
        var act = new Action(() => sessionKey.Export());

        // Assert
        act.ShouldThrow<Exception>();
    }
}
