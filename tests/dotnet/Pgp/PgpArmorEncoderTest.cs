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

    [Theory]
    [InlineData(1, PgpBlockType.Message)]
    [InlineData(119, PgpBlockType.Signature)]
    [InlineData(4096, PgpBlockType.PrivateKey)]
    [InlineData(65536, PgpBlockType.PublicKey)]
    [InlineData(1048576, PgpBlockType.Message)]
    public void Encode_ToArraySegment_AllocatesOutputBufferOnce(int messageLength, PgpBlockType blockType)
    {
        // Arrange
        var message = new byte[messageLength];
        new Random(messageLength).NextBytes(message);

        // Act
        var armoredBlock = PgpArmorEncoder.Encode(message, blockType);

        // Assert
        armoredBlock.Array.Should().NotBeNull().And.HaveCount(PgpArmorEncoder.GetMaxLengthAfterEncoding(messageLength));
        PgpArmorDecoder.Decode(armoredBlock).ToArray().Should().Equal(message);
    }
}
