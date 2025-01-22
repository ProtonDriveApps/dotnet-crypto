namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorEncodingStreamTest
{
    [Fact]
    public void Write_WritesWithArmorEncoding()
    {
        // Arrange
        var outputStream = new MemoryStream();

        var stream = PgpArmorEncodingStream.Open(outputStream, PgpBlockType.Message);

        using var messageReader = new StreamReader(outputStream);

        // Act
        stream.Write(PgpSamples.DataPacket);
        stream.Close();

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();

        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
        message.ShouldEndWith("-----END PGP MESSAGE-----");
    }
}
