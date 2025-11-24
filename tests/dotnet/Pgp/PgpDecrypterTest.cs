namespace Proton.Cryptography.Tests.Pgp;

public class PgpDecrypterTest
{
    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void DecryptSessionKey_DecryptsSessionKey(PgpProfile profile)
    {
        // Arrange
        var privateKey = profile == PgpProfile.Proton ? PgpSamples.PrivateKey : PgpSamples.PrivateKeyV6;
        var keyPacket = profile == PgpProfile.Proton ? PgpSamples.KeyPacket : PgpSamples.KeyPacketV6;

        // Act
        var sessionKey = PgpDecrypter.DecryptSessionKey(keyPacket, privateKey);

        // Assert
        sessionKey.Should().NotBeNull();
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void DecryptSessionKey_DecryptsSessionKeyWithExtensionMethod(PgpProfile profile)
    {
        // Arrange
        var privateKey = profile == PgpProfile.Proton ? PgpSamples.PrivateKey : PgpSamples.PrivateKeyV6;
        var keyPacket = profile == PgpProfile.Proton ? PgpSamples.KeyPacket : PgpSamples.KeyPacketV6;

        // Act
        var sessionKey = privateKey.DecryptSessionKey(keyPacket);

        // Assert
        sessionKey.Should().NotBeNull();
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPrivateKey()
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(PgpSamples.KeyBasedArmoredUnsignedMessage);

        // Act
        var output = PgpDecrypter.Decrypt(input, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        var outputString = Encoding.UTF8.GetString(output);
        outputString.Should().Be(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPrivateKeyV6()
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(PgpSamples.KeyBasedArmoredUnsignedAeadMessage);

        // Act
        var output = PgpDecrypter.Decrypt(input, PgpSamples.PrivateKeyV6, PgpEncoding.AsciiArmor);

        // Assert
        var outputString = Encoding.UTF8.GetString(output);
        outputString.Should().Be(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPassword()
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(PgpSamples.PasswordBasedArmoredUnsignedMessage);

        // Act
        var output = PgpDecrypter.Decrypt(input, PgpSamples.Password, PgpEncoding.AsciiArmor);

        // Assert
        var outputString = Encoding.UTF8.GetString(output);
        outputString.Should().Be(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsDataPacket_WithSessionKey()
    {
        // Arrange
        var dataPacket = Convert.FromBase64String(PgpSamples.LongDataPacket);

        // Act
        var output = PgpDecrypter.Decrypt(dataPacket, PgpSamples.SessionKey);

        // Assert
        var outputString = Encoding.UTF8.GetString(output);
        outputString.Should().Be(PgpSamples.LongPlainText);
    }

    [Theory]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredSignedMessage)]
    [InlineData(PgpVerificationStatus.Failed, PgpSamples.KeyBasedArmoredMessageWithInvalidSignature)]
    [InlineData(PgpVerificationStatus.NoVerifier, PgpSamples.KeyBasedArmoredMessageWithNonMatchingSignature)]
    [InlineData(PgpVerificationStatus.NotSigned, PgpSamples.KeyBasedArmoredUnsignedMessage)]
    public void Decrypt_ReturnsExpectedVerificationStatus_WhenSignatureIsAttached(PgpVerificationStatus expectedStatus, string armoredInput)
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(armoredInput);

        // Act
        PgpDecrypter.DecryptAndVerify(input, PgpSamples.PrivateKey, PgpSamples.PublicKey, out var verificationResult, PgpEncoding.AsciiArmor);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredSignature, EncryptionState.Plain)]
    [InlineData(PgpVerificationStatus.Ok, PgpSamples.ArmoredEncryptedSignature, EncryptionState.Encrypted)]
    [InlineData(PgpVerificationStatus.NotSigned, "", EncryptionState.Plain)]
    [InlineData(PgpVerificationStatus.Failed, PgpSamples.ArmoredInvalidSignature, EncryptionState.Plain)]
    public void Decrypt_ReturnsExpectedVerificationStatus_WhenSignatureIsDetached(
        PgpVerificationStatus expectedStatus,
        string signatureInput,
        EncryptionState encryptionState)
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(PgpSamples.KeyBasedArmoredUnsignedMessage);
        var detachedSignature = Encoding.ASCII.GetBytes(signatureInput);

        // Act
        PgpDecrypter.DecryptAndVerify(
            input,
            PgpSamples.PrivateKey,
            detachedSignature,
            PgpSamples.PublicKey,
            out var verificationResult,
            PgpEncoding.AsciiArmor,
            PgpEncoding.AsciiArmor,
            encryptionState);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }
}
