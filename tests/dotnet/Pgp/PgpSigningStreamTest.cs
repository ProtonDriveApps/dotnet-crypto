namespace Proton.Cryptography.Tests.Pgp;

public class PgpSigningStreamTest
{
    [Theory]
    [InlineData(SigningOutputType.SignatureOnly)]
    [InlineData(SigningOutputType.FullMessage)]
    public void Close_WritesExpectedOutput(SigningOutputType outputType)
    {
        // Arrange
        using var signatureOutputStream = new MemoryStream();
        using var stream = PgpSigningStream.Open(signatureOutputStream, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor, outputType);
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.LongPlainText));

        using var signatureReader = new StreamReader(signatureOutputStream);

        // Act
        stream.Close();

        // Assert
        signatureOutputStream.Seek(0, SeekOrigin.Begin);
        var signature = signatureReader.ReadToEnd();
        var expectedBlockTypeString = outputType == SigningOutputType.FullMessage ? "MESSAGE" : "SIGNATURE";
        signature.Should().StartWith($"-----BEGIN PGP {expectedBlockTypeString}-----");
        signature.Should().EndWith($"-----END PGP {expectedBlockTypeString}-----");
    }
}
