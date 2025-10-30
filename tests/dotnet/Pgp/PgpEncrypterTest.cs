namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpEncrypterTest
{
    [Fact]
    public void Encrypt_Succeeds()
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(Encoding.UTF8.GetBytes(PgpSamples.PlainText), PgpSamples.PublicKey, PgpEncoding.AsciiArmor);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
    }

    [Fact]
    public void Encrypt_OutputsAttachedSignature()
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKey,
            PgpSamples.PrivateKey,
            PgpEncoding.AsciiArmor);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
    }

    [Fact]
    public void Encrypt_OutputsDetachedSignature()
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKey,
            PgpSamples.PrivateKey,
            out var signatureBytes,
            PgpEncoding.AsciiArmor);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        var signature = Encoding.UTF8.GetString(signatureBytes);

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");
    }

    [Fact]
    public void Encrypt_Succeeds_WithCompression()
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKey,
            PgpEncoding.AsciiArmor,
            PgpCompression.Default);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Encrypt_Succeeds_WithKeyV6(PgpProfile profile)
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKeyV6,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");

        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Encrypt_Has_Valid_Sk_And_Dp_WithKeyV6(PgpProfile profile)
    {
        // Act
        var sessionKey = profile == PgpProfile.ProtonAead
            ? PgpSessionKey.ImportForAead(PgpSamples.SessionKeyToken, SymmetricCipher.Aes256)
            : PgpSessionKey.Import(PgpSamples.SessionKeyToken, SymmetricCipher.Aes256);

        var messageBytes = PgpEncrypter.Encrypt(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            new EncryptionSecrets(PgpSamples.PublicKeyV6, sessionKey),
            PgpEncoding.None,
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
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void EncryptAndSign_WithV6Key_Succeeds_AttachedSignature(PgpProfile profile)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKeyV6,
            PgpSamples.PrivateKeyV6,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");

        var decryptedBytes = PgpSamples.PrivateKeyV6.DecryptAndVerify(messageBytes, PgpSamples.PublicKeyV6, out var verificationResult, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void EncryptAndSign_WithV6Key_Succeeds_DetachedSignature(PgpProfile profile)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptAndSign(
            Encoding.UTF8.GetBytes(PgpSamples.PlainText),
            PgpSamples.PublicKeyV6,
            PgpSamples.PrivateKey,
            out var signatureBytes,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        var signature = Encoding.UTF8.GetString(signatureBytes);

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");

        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(4, PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(4, PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(6, PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(6, PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(6, PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Encrypt_WithDifferentEncodings_CanBeDecrypted(
        int keyVersion,
        PgpProfile profile,
        PgpEncoding encoding)
    {
        // Arrange
        var publicKey = keyVersion == 4 ? PgpSamples.PublicKey : PgpSamples.PublicKeyV6;
        var privateKey = keyVersion == 4 ? PgpSamples.PrivateKey : PgpSamples.PrivateKeyV6;
        var plainData = Encoding.UTF8.GetBytes(PgpSamples.PlainText);

        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            plainData,
            publicKey,
            encoding,
            profile: profile);

        // Assert
        var decryptedBytes = privateKey.Decrypt(messageBytes, encoding);
        decryptedBytes.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(4, PgpProfile.Proton, PgpCompression.None)]
    [InlineData(4, PgpProfile.Proton, PgpCompression.Default)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.None)]
    [InlineData(6, PgpProfile.Proton, PgpCompression.Default)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.None)]
    [InlineData(6, PgpProfile.ProtonAead, PgpCompression.Default)]
    public void Encrypt_WithDifferentCompression_CanBeDecrypted(int keyVersion, PgpProfile profile, PgpCompression compression)
    {
        // Arrange
        var publicKey = keyVersion == 4 ? PgpSamples.PublicKey : PgpSamples.PublicKeyV6;
        var privateKey = keyVersion == 4 ? PgpSamples.PrivateKey : PgpSamples.PrivateKeyV6;
        var plainData = Encoding.UTF8.GetBytes(PgpSamples.PlainText);

        // Act
        var messageBytes = PgpEncrypter.Encrypt(
            plainData,
            publicKey,
            outputCompression: compression,
            profile: profile);

        // Assert
        var decryptedBytes = privateKey.Decrypt(messageBytes);
        decryptedBytes.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(PgpProfile.ProtonAead)]
    public void EncryptText_WithV6Key_Succeeds(PgpProfile profile)
    {
        // Act
        var messageBytes = PgpEncrypter.EncryptText(
            PgpSamples.PlainText,
            PgpSamples.PublicKeyV6,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.ProtonAead)]
    public void EncryptToStream_WithV6Key_Succeeds(PgpProfile profile)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        var plainData = Encoding.UTF8.GetBytes(PgpSamples.PlainText);

        // Act
        PgpEncrypter.EncryptToStream(
            plainData,
            PgpSamples.PublicKeyV6,
            outputStream,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(outputStream);
        var message = reader.ReadToEnd();
        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");

        var messageBytes = Encoding.UTF8.GetBytes(message);
        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void EncryptAndSignToStream_WithV6Key_Succeeds(PgpProfile profile)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        var plainData = Encoding.UTF8.GetBytes(PgpSamples.PlainText);

        // Act
        PgpEncrypter.EncryptAndSignToStream(
            plainData,
            PgpSamples.PublicKeyV6,
            outputStream,
            PgpSamples.PrivateKey,
            PgpEncoding.AsciiArmor,
            profile: profile);

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var messageBytes = outputStream.ToArray();

        var decryptedBytes = PgpSamples.PrivateKeyV6.DecryptAndVerify(messageBytes, PgpSamples.PublicKey, out var verificationResult, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }
}
