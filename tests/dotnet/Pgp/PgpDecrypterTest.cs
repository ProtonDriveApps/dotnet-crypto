namespace Proton.Cryptography.Tests.Pgp;

public class PgpDecrypterTest
{
    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Export_Succeeds(PgpProfile profile)
    {
        // Arrange
        var sessionKey = profile == PgpProfile.Proton ? PgpSamples.SessionKey : PgpSamples.SessionKeyV6;

        // Act
        var token = sessionKey.Export();

        // Assert
        token.Should().Equal(PgpSamples.SessionKeyToken);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void DecryptSessionKey_DecryptsSessionKey(PgpProfile profile)
    {
        // Arrange
        var (privateKey, keyPacket) = profile == PgpProfile.Proton
            ? (PgpSamples.UnlockedPrivateKey, PgpSamples.KeyPacket)
            : (PgpSamples.UnlockedPrivateKeyV6, PgpSamples.KeyPacketV6);

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
        var privateKey = profile == PgpProfile.Proton ? PgpSamples.UnlockedPrivateKey : PgpSamples.UnlockedPrivateKeyV6;
        var keyPacket = profile == PgpProfile.Proton ? PgpSamples.KeyPacket : PgpSamples.KeyPacketV6;

        // Act
        var sessionKey = privateKey.DecryptSessionKey(keyPacket);

        // Assert
        sessionKey.Should().NotBeNull();
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPrivateKey()
    {
        // Act
        var output = PgpDecrypter.Decrypt(PgpSamples.KeyBasedArmoredUnsignedMessage, PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        output.Should().Equal(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPrivateKeyV6()
    {
        // Act
        var output = PgpDecrypter.Decrypt(PgpSamples.KeyBasedArmoredUnsignedAeadMessage, PgpSamples.UnlockedPrivateKeyV6, PgpEncoding.AsciiArmor);

        // Assert
        output.Should().Equal(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsMessage_WithPassword()
    {
        // Act
        var output = PgpDecrypter.Decrypt(PgpSamples.PasswordBasedArmoredUnsignedMessage, PgpSamples.Password, PgpEncoding.AsciiArmor);

        // Assert
        output.Should().Equal(PgpSamples.PlainText);
    }

    [Fact]
    public void Decrypt_DecryptsDataPacket_WithSessionKey()
    {
        // Act
        var output = PgpDecrypter.Decrypt(PgpSamples.LongDataPacket, PgpSamples.SessionKey);

        // Assert
        output.Should().Equal(PgpSamples.LongPlainText);
    }

    [Theory]
    [MemberData(nameof(VerificationTestData.AttachedSignatures), MemberType = typeof(VerificationTestData))]
    public void Decrypt_ReturnsExpectedVerificationStatus_WhenSignatureIsAttached(Func<byte[]> armoredInput, PgpVerificationStatus expectedStatus)
    {
        // Act
        PgpDecrypter.DecryptAndVerify(
            armoredInput.Invoke(),
            PgpSamples.UnlockedPrivateKey,
            PgpSamples.PublicKey,
            out var verificationResult,
            PgpEncoding.AsciiArmor);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [MemberData(nameof(VerificationTestData.DetachedSignatures), MemberType = typeof(VerificationTestData))]
    public void Decrypt_ReturnsExpectedVerificationStatus_WhenSignatureIsDetached(
        Func<byte[]> signatureInput,
        PgpEncoding signatureEncoding,
        EncryptionState signatureEncryptionState,
        PgpVerificationStatus expectedStatus)
    {
        // Act
        PgpDecrypter.DecryptAndVerify(
            PgpSamples.KeyBasedArmoredUnsignedMessage,
            PgpSamples.UnlockedPrivateKey,
            signatureInput.Invoke(),
            PgpSamples.PublicKey,
            out var verificationResult,
            PgpEncoding.AsciiArmor,
            signatureEncoding,
            signatureEncryptionState);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }
}
