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
        using var stream = PgpSigningStream.Open(signatureOutputStream, PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor, outputType);
        stream.Write(PgpSamples.LongPlainText);

        using var signatureReader = new StreamReader(signatureOutputStream);

        // Act
        stream.Close();

        // Assert
        var signatureBytes = signatureOutputStream.ToArray();
        var expectedHeader = outputType == SigningOutputType.FullMessage ? PgpArmorHeaders.Message : PgpArmorHeaders.Signature;
        signatureBytes.Should().StartWith(expectedHeader);

        var decode = () => PgpArmorDecoder.Decode(signatureBytes);
        decode.Should().NotThrow();
    }

    [Fact]
    public void Write_RethrowsOutputStreamException_WhenOutputStreamFails()
    {
        // Arrange
        const string simulatedOutputStreamFailureMessage = "Simulated output stream failure.";

        var outputStream = new FailingStream(
            new MemoryStream(),
            failWhenPositionExceeds: 100,
            createException: () => new InvalidOperationException(simulatedOutputStreamFailureMessage));

        // Act
        var act = () =>
        {
            var stream = PgpSigningStream.Open(outputStream, PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor);
            stream.Write(PgpSamples.LongPlainText);
            stream.Close();
        };

        // Assert
        var exception = act.Should().Throw<InvalidOperationException>().Which;
        exception.Message.Should().Be(simulatedOutputStreamFailureMessage);
        exception.StackTrace.Should().Contain(nameof(FailingStream));
    }
}
