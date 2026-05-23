using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Tests.Pgp;

public class PgpSessionKeyTest
{
    [Fact]
    public void Generate_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Generate(PgpSamples.SessionKeyCipher);

        // Assert
        ((IForeignHandleProxy)sessionKey).ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Generate_For_Aead_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.GenerateForAead(PgpSamples.SessionKeyCipher);

        // Assert
        ((IForeignHandleProxy)sessionKey).ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Import_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Assert
        ((IForeignHandleProxy)sessionKey).ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Import_Aead_Succeeds()
    {
        // Act
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Assert
        ((IForeignHandleProxy)sessionKey).ForeignHandle.IsInvalid.Should().BeFalse();
    }

    [Fact]
    public void Export_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var token = sessionKey.Export();

        // Assert
        token.Should().Equal(PgpSamples.SessionKeyToken);
    }

    [Fact]
    public void TryGetCipher_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var success = sessionKey.TryGetCipher(out var cipher);

        // Assert
        cipher.Should().Be(PgpSamples.SessionKeyCipher);
        success.Should().BeTrue();
    }

    [Fact]
    public void Export_Aead_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var token = sessionKey.Export();

        // Assert
        token.Should().Equal(PgpSamples.SessionKeyToken);
    }

    [Fact]
    public void TryGetCipher_WithAead_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);

        // Act
        var success = sessionKey.TryGetCipher(out var cipher);

        // Assert
        success.Should().BeTrue();
        cipher.Should().Be(PgpSamples.SessionKeyCipher);
    }

    [Fact]
    public void EncryptToStream_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.Import(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var outputStream = new MemoryStream();

        // Act
        sessionKey.EncryptToStream(PgpSamples.PlainText, outputStream);

        // Assert
        outputStream.Seek(2, SeekOrigin.Begin);
        // SEIPDv1
        outputStream.ReadByte().Should().Be(1);
    }

    [Fact]
    public void EncryptToStream_With_Aead_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var outputStream = new MemoryStream();

        // Act
        sessionKey.EncryptToStream(PgpSamples.PlainText, outputStream);

        // Assert
        outputStream.Seek(2, SeekOrigin.Begin);
        // SEIPDv2
        outputStream.ReadByte().Should().Be(2);
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
        keyPacketOutputStream.Seek(2, SeekOrigin.Begin);
        // PKESKv3
        keyPacketOutputStream.ReadByte().Should().Be(3);
        keyPacketOutputStream.ToArray().Length.Should().Be(PgpSamples.KeyPacket.Length);
    }

    [Fact]
    public void ToKeyPacket_With_Aead_Succeeds()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var keyPacketOutputStream = new MemoryStream();

        // Act
        sessionKey.ToKeyPackets(PgpSamples.PublicKeyV6, keyPacketOutputStream);

        // Assert
        // Should be PKESKv6 (1st byte of body is 6)
        keyPacketOutputStream.Seek(2, SeekOrigin.Begin);
        keyPacketOutputStream.ReadByte().Should().Be(6);
    }

    [Fact]
    public void ToKeyPacket_With_Aead_And_No_Aead_Public_Key_Succeeds_And_Overrides_Flags()
    {
        // Arrange
        using var sessionKey = PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, PgpSamples.SessionKeyCipher);
        using var keyPacketOutputStream = new MemoryStream();

        // Act
        sessionKey.ToKeyPackets(PgpSamples.PublicKey, keyPacketOutputStream);

        // Assert
        // Must be PKESKv6 (1st byte of body is 6), even if public key does not have SEIPDv2 flag
        keyPacketOutputStream.Seek(2, SeekOrigin.Begin);
        keyPacketOutputStream.ReadByte().Should().Be(6);
    }

    [Fact]
    public void IsAead_Without_Aead_Is_False()
    {
        // Act
        using var sessionKey = PgpSessionKey.Generate(PgpSamples.SessionKeyCipher);

        // Assert
        sessionKey.IsAead().Should().BeFalse();
    }

    [Fact]
    public void IsAead_With_Aead_Is_True()
    {
        // Act
        using var sessionKey = PgpSessionKey.GenerateForAead(PgpSamples.SessionKeyCipher);

        // Assert
        sessionKey.IsAead().Should().BeTrue();
    }

    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var sessionKey = default(PgpSessionKey);

        // Act
        var act = new Action(() => sessionKey.Export());

        // Assert
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void Is_Aead_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var sessionKey = default(PgpSessionKey);

        // Act
        var act = new Action(() => sessionKey.IsAead());

        // Assert
        act.Should().Throw<Exception>();
    }
}
