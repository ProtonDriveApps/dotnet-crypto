namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpDecryptingStreamTest
{
    [Fact]
    public void Read_DecryptsMessage_WithPrivateKey()
    {
        // Arrange
        using var inputStream = new AsciiStream(PgpSamples.KeyBasedArmoredUnsignedMessage);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(PgpSamples.PlainText);
    }

    [Fact]
    public void Read_DecryptsMessage_WithPassword()
    {
        // Arrange
        using var inputStream = new AsciiStream(PgpSamples.PasswordBasedArmoredUnsignedMessage);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.Password, PgpEncoding.AsciiArmor);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(PgpSamples.PlainText);
    }

    [Fact]
    public void Read_DecryptsDataPacket_WithSessionKey()
    {
        // Arrange
        var dataPacket = Convert.FromBase64String(PgpSamples.LongDataPacket);

        using var inputStream = new MemoryStream(dataPacket);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.SessionKey);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(PgpSamples.LongPlainText);
    }

    [Theory]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredSignedMessage)]
    [InlineData(PgpVerificationStatus.Failed, PgpSamples.KeyBasedArmoredMessageWithInvalidSignature)]
    [InlineData(PgpVerificationStatus.NoVerifier, PgpSamples.KeyBasedArmoredMessageWithNonMatchingSignature)]
    [InlineData(PgpVerificationStatus.NotSigned, PgpSamples.KeyBasedArmoredUnsignedMessage)]
    public void GetVerificationResult_ReturnsExpectedStatus_WhenSignatureIsAttached(PgpVerificationStatus expectedStatus, string input)
    {
        // Arrange
        using var inputStream = new AsciiStream(input);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.PrivateKey, PgpSamples.PublicKey, PgpEncoding.AsciiArmor);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);
        streamReader.ReadToEnd();

        // Act
        var result = stream.GetVerificationResult();

        // Assert
        result.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredSignature, EncryptionState.Plain)]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredEncryptedSignature, EncryptionState.Encrypted)]
    [InlineData(PgpVerificationStatus.NotSigned, "", EncryptionState.Plain)]
    [InlineData(PgpVerificationStatus.Failed, PgpSamples.ArmoredInvalidSignature, EncryptionState.Plain)]
    public void GetVerificationResult_ReturnsExpectedStatus_WhenSignatureIsDetached(
        PgpVerificationStatus expectedStatus,
        string signatureInput,
        EncryptionState encryptionState)
    {
        // Arrange
        using var inputStream = new AsciiStream(PgpSamples.KeyBasedArmoredUnsignedMessage);
        var detachedSignature = Encoding.ASCII.GetBytes(signatureInput);

        using var stream = PgpDecryptingStream.Open(
            inputStream,
            PgpSamples.PrivateKey,
            detachedSignature,
            PgpSamples.PublicKey,
            PgpEncoding.AsciiArmor,
            PgpEncoding.AsciiArmor,
            encryptionState);

        using var streamReader = new StreamReader(stream, Encoding.UTF8);
        streamReader.ReadToEnd();

        // Act
        var result = stream.GetVerificationResult();

        // Assert
        result.Status.Should().Be(expectedStatus);
    }
}
