namespace Proton.Cryptography.Tests.Pgp;

public class PgpMessageTest
{
    [Fact]
    public void GetKeyPacketsLength_Succeeds()
    {
        // Arrange
        var messageBytes = new byte[PgpSamples.KeyPacket.Length + PgpSamples.DataPacket.Length];
        PgpSamples.KeyPacket.CopyTo(messageBytes.AsSpan());
        PgpSamples.DataPacket.CopyTo(messageBytes.AsSpan(PgpSamples.KeyPacket.Length));

        using var message = PgpMessage.Open(messageBytes);

        // Act
        var keyPacketsLength = message.GetKeyPacketsLength();

        // Assert
        keyPacketsLength.Should().Be(PgpSamples.KeyPacket.Length);
    }

    [Fact]
    public void GetKeyPacketsLength_Succeeds_WhenMessageIsArmored()
    {
        // Arrange
        using var message = PgpMessage.Open(PgpSamples.KeyBasedArmoredUnsignedMessage, PgpEncoding.AsciiArmor);

        // Act
        var keyPacketsLength = message.GetKeyPacketsLength();

        // Assert
        keyPacketsLength.Should().Be(PgpSamples.KeyPacket.Length);
    }
}
