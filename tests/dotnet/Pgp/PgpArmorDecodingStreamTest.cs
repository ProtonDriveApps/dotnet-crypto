namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorDecodingStreamTest
{
    [Fact]
    public void Read_ProducesDecodedBytes()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.KeyBasedArmoredUnsignedMessage);
        using var outputStream = new MemoryStream();

        using var stream = PgpArmorDecodingStream.Open(inputStream);

        // Act
        stream.CopyTo(outputStream);

        // Assert
        var decryptedBytes = PgpDecrypter.Decrypt(outputStream.GetSpan(), PgpSamples.UnlockedPrivateKey);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }
}
