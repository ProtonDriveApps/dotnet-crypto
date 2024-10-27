namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorDecodingStreamTest
{
    [Fact]
    public void Write_WritesWithArmorEncoding()
    {
        // Arrange
        using var inputStream = new MemoryStream(Encoding.ASCII.GetBytes(PgpSamples.KeyBasedArmoredUnsignedMessage));

        using var stream = PgpArmorDecodingStream.Open(inputStream);

        using var outputStream = new MemoryStream();

        // Act
        stream.CopyTo(outputStream);

        // Assert
        outputStream.Length.Should().Be(PgpSamples.KeyPacket.Length + PgpSamples.DataPacket.Length);
    }
}
