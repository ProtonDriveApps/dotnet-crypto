namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorDecoderTest
{
    [Fact]
    public void Read_ProducesDecodedBytes()
    {
        // Arrange
        using var outputStream = new MemoryStream();

        // Act
        PgpArmorDecoder.Decode(PgpSamples.KeyBasedArmoredUnsignedMessage, outputStream);

        // Assert
        var decryptedBytes = PgpDecrypter.Decrypt(outputStream.GetSpan(), PgpSamples.UnlockedPrivateKey);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }
}
