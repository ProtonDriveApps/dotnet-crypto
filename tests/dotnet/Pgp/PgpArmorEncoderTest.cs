namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorEncoderTest
{
    [Fact]
    public void Write_WritesWithArmorEncoding()
    {
        // Arrange
        var outputStream = new MemoryStream();
        using var messageReader = new StreamReader(outputStream);

        // Act
        PgpArmorEncoder.Encode(PgpSamples.DataPacket, PgpBlockType.Message, outputStream);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        message.Should().EndWith("-----END PGP MESSAGE-----");
    }
}
