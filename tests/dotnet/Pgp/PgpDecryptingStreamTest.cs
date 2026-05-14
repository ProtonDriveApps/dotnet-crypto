namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpDecryptingStreamTest
{
    [Fact]
    public void Read_DecryptsMessage_WithPrivateKey()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.KeyBasedArmoredEncryptedUnsignedMessage, writable: false);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(Encoding.UTF8.GetString(PgpSamples.PlainText));
    }

    [Fact]
    public void Read_DecryptsMessage_WithPassword()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PasswordBasedArmoredEncryptedUnsignedMessage, writable: false);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.Password, PgpEncoding.AsciiArmor);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(Encoding.UTF8.GetString(PgpSamples.PlainText));
    }

    [Fact]
    public void Read_DecryptsDataPacket_WithSessionKey()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.LongDataPacket, writable: false);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.SessionKey);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);

        // Act
        var output = streamReader.ReadToEnd();

        // Assert
        output.Should().Be(Encoding.UTF8.GetString(PgpSamples.LongPlainText));
    }

    [Fact(Timeout = 1000)]
    public void Read_OutputsPartiallyDecryptedDataPacket_WithSessionKey_WhenBufferSmallerThanPlainData()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.LongDataPacket, writable: false);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.SessionKey);

        var buffer = new byte[16];

        // Act
        var numberOfBytesRead = stream.Read(buffer);

        // Assert
        numberOfBytesRead.Should().Be(buffer.Length);
    }

    [Theory]
    [MemberData(nameof(VerificationTestData.EncryptedMessagesWithInlineSignatures), MemberType = typeof(VerificationTestData))]
    public void GetVerificationResult_ReturnsExpectedStatus_WhenSignatureIsInline(
        Func<byte[]> armoredMessage,
        PgpVerificationContext? verificationContext,
        PgpVerificationStatus expectedStatus)
    {
        // Arrange
        using var inputStream = new MemoryStream(armoredMessage.Invoke(), writable: false);

        using var stream = PgpDecryptingStream.Open(
            inputStream,
            PgpSamples.UnlockedPrivateKey,
            PgpSamples.PublicKey,
            PgpEncoding.AsciiArmor,
            verificationContext);
        using var streamReader = new StreamReader(stream, Encoding.UTF8);
        streamReader.ReadToEnd();

        // Act
        var result = stream.GetVerificationResult();

        // Assert
        result.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [MemberData(nameof(VerificationTestData.DetachedSignatures), MemberType = typeof(VerificationTestData))]
    public void GetVerificationResult_ReturnsExpectedStatus_WhenSignatureIsDetached(
        Func<byte[]> signature,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        PgpVerificationStatus expectedStatus)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.KeyBasedArmoredEncryptedUnsignedMessage, writable: false);

        using var stream = PgpDecryptingStream.Open(
            inputStream,
            PgpSamples.UnlockedPrivateKey,
            signature.Invoke(),
            PgpSamples.PublicKey,
            PgpEncoding.AsciiArmor,
            signatureEncoding,
            signatureEncryptionState);

        using var streamReader = new StreamReader(stream, Encoding.UTF8);
        streamReader.ReadToEnd();

        // Act
        var result = stream.GetVerificationResult();

        // Assert
        result.Status.Should().Be(expectedStatus);
    }
}
