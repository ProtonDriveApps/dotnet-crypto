namespace Proton.Cryptography.Tests.Pgp;

public class PgpEncoderTest
{
    [Fact]
    public void Encode_Succeeds_WhenWritingToSpan()
    {
        // Arrange
        var output = new byte[1024];

        // Act
        var numberOfBytesWritten = PgpArmorEncoder.Encode(PgpSamples.DataPacket, PgpBlockType.Message, output);

        // Assert
        numberOfBytesWritten.Should().BePositive();
    }
}
