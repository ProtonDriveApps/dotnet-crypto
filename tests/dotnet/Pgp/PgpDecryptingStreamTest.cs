namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpDecryptingStreamTest
{
    [Fact]
    public void Read_DecryptsMessage_WithPrivateKey()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.KeyBasedArmoredUnsignedMessage, writable: false);

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
        using var inputStream = new MemoryStream(PgpSamples.PasswordBasedArmoredUnsignedMessage, writable: false);

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

    [Theory]
    [MemberData(nameof(VerificationTestData.AttachedSignatures), MemberType = typeof(VerificationTestData))]
    public void GetVerificationResult_ReturnsExpectedStatus_WhenSignatureIsAttached(Func<byte[]> armoredMessage, PgpVerificationStatus expectedStatus)
    {
        // Arrange
        using var inputStream = new MemoryStream(armoredMessage.Invoke(), writable: false);

        using var stream = PgpDecryptingStream.Open(inputStream, PgpSamples.UnlockedPrivateKey, PgpSamples.PublicKey, PgpEncoding.AsciiArmor);
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
        using var inputStream = new MemoryStream(PgpSamples.KeyBasedArmoredUnsignedMessage, writable: false);

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
