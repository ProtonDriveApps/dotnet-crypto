namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorEncoderTest
{
    [Fact]
    public void Write_WritesWithArmorEncoding()
    {
        // Arrange
        var outputStream = new MemoryStream();

        // Act
        PgpArmorEncoder.Encode(PgpSamples.DataPacket, PgpBlockType.Message, outputStream);

        // Assert
        var messageBytes = outputStream.ToArray();
        messageBytes.Should().StartWith(PgpArmorHeaders.Message);

        var decode = () => PgpArmorDecoder.Decode(messageBytes);
        decode.Should().NotThrow();
    }
}
