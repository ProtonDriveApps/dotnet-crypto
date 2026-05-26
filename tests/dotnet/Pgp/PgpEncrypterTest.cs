namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpEncrypterTest
{
    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessage(PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(PgpSamples.PlainText, PgpSamples.PublicKey, encoding);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.Decrypt(messageBytes, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessageWithAttachedSignature_WhenSigningKeysProvided(PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(PgpSamples.PlainText, PgpSamples.PublicKey, PgpSamples.UnlockedPrivateKey, encoding);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.DecryptAndVerify(messageBytes, PgpSamples.PublicKey, out var verificationResult, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessageWithDetachedSignature_WhenDetachedSignatureOutputRequested(PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            PgpSamples.PlainText,
            PgpSamples.PublicKey,
            PgpSamples.UnlockedPrivateKey,
            out var signature,
            encoding);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);
        PgpEncodingAssertions.ShouldMatchEncoding(signature, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.DecryptAndVerify(
            messageBytes,
            signature.AsSpan(),
            PgpSamples.PublicKey,
            out var verificationResult,
            encoding,
            encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessage_WhenCompressionEnabled(PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(PgpSamples.PlainText, PgpSamples.PublicKey, encoding, PgpCompression.Default);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.Decrypt(messageBytes, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessage_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(PgpSamples.PlainText, PgpSamples.PublicKeyV6, encoding, profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.Decrypt(messageBytes, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Encrypt_ProducesExpectedSessionKeyPacketLayout_WhenUsingSessionKeyWithV6Key(PgpProfile profile)
    {
        // Arrange
        var sessionKey = profile == PgpProfile.ProtonAead
            ? PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, SymmetricCipher.Aes256)
            : PgpSessionKey.Import(PgpSamples.SessionKeyToken, SymmetricCipher.Aes256);

        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            PgpSamples.PlainText,
            new EncryptionSecrets(PgpSamples.PublicKeyV6, sessionKey),
            profile: profile);

        // Assert
        if (profile == PgpProfile.ProtonAead)
        {
            // For ecc key, PK is less than 191 bytes, so body is 2 byte header than
            // PKESKv6 version byte (0x06)
            messageBytes[2].Should().Be(6);
            // PKESKv6 for ecc key should be 111 followed by 3 byte header followed by
            // seipv2 = 2 version
            messageBytes[113].Should().Be(2);
        }
        else
        {
            // For ecc key, KP is less than 191 bytes and message is 2 byte header than
            // PKESKv3 version byte
            messageBytes[2].Should().Be(3);
            // PKESKv3 for ecc key should be 86 followed by 3 byte header followed by
            // seipv1 = 1 version
            messageBytes[88].Should().Be(1);
        }
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void EncryptAndSign_ProducesValidMessageWithAttachedSignature_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            PgpSamples.PlainText,
            PgpSamples.PublicKeyV6,
            PgpSamples.UnlockedPrivateKeyV6,
            encoding,
            profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(messageBytes, PgpSamples.PublicKeyV6, out var verificationResult, encoding);
        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void EncryptAndSign_ProducesValidMessageWithDetachedSignature_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            PgpSamples.PlainText,
            PgpSamples.PublicKeyV6,
            PgpSamples.UnlockedPrivateKeyV6,
            out var signature,
            encoding,
            profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);
        PgpEncodingAssertions.ShouldMatchEncoding(signature, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(
            messageBytes,
            signature,
            PgpSamples.PublicKeyV6,
            out var verificationResult,
            encoding,
            encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(4, PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(4, PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(6, PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(6, PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessage_ForMultipleKeyVersionsProfilesAndEncodings(
        int keyVersion,
        PgpProfile profile,
        PgpEncoding encoding)
    {
        // Arrange
        var publicKey = keyVersion == 4 ? PgpSamples.PublicKey : PgpSamples.PublicKeyV6;
        var privateKey = keyVersion == 4 ? PgpSamples.UnlockedPrivateKey : PgpSamples.UnlockedPrivateKeyV6;

        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            PgpSamples.PlainText,
            publicKey,
            encoding,
            profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = privateKey.Decrypt(messageBytes, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(4, PgpProfile.Proton, PgpCompression.None, PgpEncoding.None)]
    [InlineData(4, PgpProfile.Proton, PgpCompression.Default, PgpEncoding.None)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.None, PgpEncoding.None)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.Default, PgpEncoding.None)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.None, PgpEncoding.None)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.Default, PgpEncoding.None)]
    [InlineData(4, PgpProfile.Proton, PgpCompression.None, PgpEncoding.AsciiArmor)]
    [InlineData(4, PgpProfile.Proton, PgpCompression.Default, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.None, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.Default, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.None, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.Default, PgpEncoding.AsciiArmor)]
    public void Encrypt_ProducesValidMessage_ForMultipleKeyVersionsProfilesCompressionAndEncodings(
        int keyVersion,
        PgpProfile profile,
        PgpCompression compression,
        PgpEncoding encoding)
    {
        // Arrange
        var (publicKey, privateKey) = keyVersion == 4
            ? (PgpSamples.PublicKey, PgpSamples.UnlockedPrivateKey)
            : (PgpSamples.PublicKeyV6, PgpSamples.UnlockedPrivateKeyV6);

        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            PgpSamples.PlainText,
            publicKey,
            encoding,
            outputCompression: compression,
            profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedBytes = privateKey.Decrypt(messageBytes, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void EncryptText_ProducesValidMessage_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        var plainText = Encoding.UTF8.GetString(PgpSamples.PlainText);

        // Act
        var messageBytes = PgpEncrypter.EncryptText(plainText, PgpSamples.PublicKeyV6, encoding, profile: profile);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(messageBytes, encoding);

        var decryptedText = PgpSamples.UnlockedPrivateKeyV6.DecryptText(messageBytes, encoding);

        decryptedText.Should().Be(plainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void EncryptToStream_ProducesValidMessage_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        var plainData = PgpSamples.PlainText;

        // Act
        PgpEncrypter.EncryptToStream(
            plainData,
            PgpSamples.PublicKeyV6,
            outputStream,
            encoding,
            profile: profile);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.Decrypt(outputStream.GetSpan(), encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void EncryptAndSignToStream_ProducesValidMessageWithAttachedSignature_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        var plainData = PgpSamples.PlainText;

        // Act
        PgpEncrypter.EncryptAndSignToStream(
            plainData,
            PgpSamples.PublicKeyV6,
            outputStream,
            PgpSamples.UnlockedPrivateKey,
            encoding,
            profile: profile);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(outputStream.GetSpan(), PgpSamples.PublicKey, out var verificationResult, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }
}
