using System.Security.Cryptography;

namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpEncryptingStreamTest
{
    [Fact]
    public void Write_Encrypts()
    {
        // Arrange
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.Open(outputStream, PgpSamples.PublicKey, PgpEncoding.AsciiArmor);

        using var messageReader = new StreamReader(outputStream);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
    }

    [Fact]
    public void Write_WritesAttachedSignature()
    {
        // Arrange
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.Open(outputStream, PgpSamples.PublicKey, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);

        using var messageReader = new StreamReader(outputStream);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
    }

    [Fact]
    public void Write_WritesDetachedSignature()
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.Open(outputStream, signatureOutputStream, PgpSamples.PublicKey, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);

        using var signatureReader = new StreamReader(signatureOutputStream);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        signatureOutputStream.Seek(0, SeekOrigin.Begin);
        var signature = signatureReader.ReadToEnd();

        signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");
    }

    [Fact]
    public void Write_WritesSeparateKeyAndDataPackets()
    {
        // Arrange
        using var dataPacketStream = new MemoryStream();
        using var keyPacketStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplit(dataPacketStream, keyPacketStream, PgpSamples.PublicKey);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        dataPacketStream.Length.Should().BePositive();
        keyPacketStream.Length.Should().BePositive();
    }

    [Fact]
    public void Write_WritesSeparateKeyAndDataPackets_AndDetachedSignature()
    {
        // Arrange
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplit(
            dataPacketOutputStream,
            keyPacketOutputStream,
            signatureOutputStream,
            PgpSamples.PublicKey,
            PgpSamples.PrivateKey);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        dataPacketOutputStream.Length.Should().BePositive();
        keyPacketOutputStream.Length.Should().BePositive();
        signatureOutputStream.Length.Should().BePositive();
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Write_Encrypts_WithV6Key(PgpProfile profile)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var stream = PgpEncryptingStream.Open(outputStream, PgpSamples.PublicKeyV6, PgpEncoding.AsciiArmor, profile: profile);
        using var messageReader = new StreamReader(outputStream);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var message = messageReader.ReadToEnd();

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");

        // Verify it can be decrypted
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Write_WritesAttachedSignature_WithV6Key(PgpProfile profile)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var stream = PgpEncryptingStream.Open(outputStream, PgpSamples.PublicKeyV6, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor, profile: profile);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        outputStream.Seek(0, SeekOrigin.Begin);
        var messageBytes = outputStream.ToArray();

        var decryptedBytes = PgpSamples.PrivateKeyV6.DecryptAndVerify(messageBytes, PgpSamples.PublicKey, out var verificationResult, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Write_WritesDetachedSignature_WithV6Key(PgpProfile profile)
    {
        // Arrange
        using var outputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();
        using var stream = PgpEncryptingStream.Open(
            outputStream,
            signatureOutputStream,
            PgpSamples.PublicKeyV6,
            PgpSamples.PrivateKey,
            PgpEncoding.AsciiArmor,
            profile: profile);
        using var signatureReader = new StreamReader(signatureOutputStream);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        signatureOutputStream.Seek(0, SeekOrigin.Begin);
        var signature = signatureReader.ReadToEnd();

        signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");

        // Verify message can be decrypted
        outputStream.Seek(0, SeekOrigin.Begin);
        var messageBytes = outputStream.ToArray();
        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void OpenSplit_Writes_WithV6Key(PgpProfile profile)
    {
        // Arrange
        using var dataPacketStream = new MemoryStream();
        using var keyPacketStream = new MemoryStream();
        using var stream = PgpEncryptingStream.OpenSplit(dataPacketStream, keyPacketStream, PgpSamples.PublicKeyV6, profile: profile);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        dataPacketStream.Length.Should().BePositive();
        keyPacketStream.Length.Should().BePositive();

        // Verify the split packets can be decrypted when combined
        var combinedMessage = new byte[keyPacketStream.Length + dataPacketStream.Length];
        keyPacketStream.Seek(0, SeekOrigin.Begin);
        dataPacketStream.Seek(0, SeekOrigin.Begin);
        keyPacketStream.Read(combinedMessage, 0, (int)keyPacketStream.Length);
        dataPacketStream.Read(combinedMessage, (int)keyPacketStream.Length, (int)dataPacketStream.Length);

        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(combinedMessage);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void OpenSplit_WritesSeparateKeyAndDataPackets_AndDetachedSignature_WithV6Key(PgpProfile profile)
    {
        // Arrange
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();
        using var stream = PgpEncryptingStream.OpenSplit(
            dataPacketOutputStream,
            keyPacketOutputStream,
            signatureOutputStream,
            PgpSamples.PublicKeyV6,
            PgpSamples.PrivateKey,
            profile: profile);

        // Act
        stream.Write(Encoding.UTF8.GetBytes(PgpSamples.PlainText));
        stream.Close();

        // Assert
        dataPacketOutputStream.Length.Should().BePositive();
        keyPacketOutputStream.Length.Should().BePositive();
        signatureOutputStream.Length.Should().BePositive();

        // Verify the split packets can be decrypted when combined
        var combinedMessage = new byte[keyPacketOutputStream.Length + dataPacketOutputStream.Length];
        keyPacketOutputStream.Seek(0, SeekOrigin.Begin);
        dataPacketOutputStream.Seek(0, SeekOrigin.Begin);
        keyPacketOutputStream.Read(combinedMessage, 0, (int)keyPacketOutputStream.Length);
        dataPacketOutputStream.Read(combinedMessage, (int)keyPacketOutputStream.Length, (int)dataPacketOutputStream.Length);

        var decryptedBytes = PgpSamples.PrivateKeyV6.Decrypt(combinedMessage);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        decryptedText.Should().Be(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 2)]
    [InlineData(1, 16)]
    [InlineData(1, 4096)]
    [InlineData(2, 1)]
    [InlineData(2, 2)]
    [InlineData(2, 16)]
    [InlineData(2, 4096)]
    [InlineData(100, 1)]
    [InlineData(100, 2)]
    [InlineData(100, 16)]
    [InlineData(100, 4096)]
    [InlineData(256_000, 1)]
    [InlineData(256_000, 2)]
    [InlineData(256_000, 16)]
    [InlineData(256_000, 4096)]
    public void Read_EncryptsWithoutArmor(int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData, 0, plainData.Length, false, true);
        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey);

        var readBuffer = new byte[readBufferSize].AsSpan();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = stream.Read(readBuffer);
            encryptedDataStream.Write(readBuffer[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = encryptedDataStream.ToArray();

        var decryptedData = PgpSamples.PrivateKey.Decrypt(message);

        decryptedData.Should().Equal(plainData);
    }

    [Fact]
    public void Read_DoesNotThrow_WhenUsingLegacyArrayOverload()
    {
        // Arrange
        const int length = 16;

        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData, 0, plainData.Length, false, true);
        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey);

        var readBuffer = new byte[length];

        // Act
        var act = (Stream s) => s.Read(readBuffer, 0, length);

        // Assert
        stream.Invoking(act).Should().NotThrow();
    }

    [Theory]
    [InlineData(PgpProfile.Proton, 100, 1)]
    [InlineData(PgpProfile.Proton, 100, 4096)]
    [InlineData(PgpProfile.Proton, 256_000, 4096)]
    [InlineData(PgpProfile.ProtonAead, 100, 1)]
    [InlineData(PgpProfile.ProtonAead, 100, 4096)]
    [InlineData(PgpProfile.ProtonAead, 256_000, 4096)]
    public void Read_EncryptsWithV6Key(PgpProfile profile, int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, profile: profile);

        var readBuffer = new byte[readBufferSize].AsSpan();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = stream.Read(readBuffer);
            encryptedDataStream.Write(readBuffer[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = encryptedDataStream.ToArray();

        var decryptedData = PgpSamples.PrivateKeyV6.Decrypt(message);

        decryptedData.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 2)]
    [InlineData(1, 16)]
    [InlineData(1, 4096)]
    [InlineData(2, 1)]
    [InlineData(2, 2)]
    [InlineData(2, 16)]
    [InlineData(2, 4096)]
    [InlineData(100, 1)]
    [InlineData(100, 2)]
    [InlineData(100, 16)]
    [InlineData(100, 4096)]
    [InlineData(256_000, 1)]
    [InlineData(256_000, 2)]
    [InlineData(256_000, 16)]
    [InlineData(256_000, 4096)]
    public async Task ReadAsync_EncryptsWithoutArmor(int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        await using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey);

        var readBuffer = new byte[readBufferSize].AsMemory();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = await stream.ReadAsync(readBuffer, CancellationToken.None);
            encryptedDataStream.Write(readBuffer.Span[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = encryptedDataStream.ToArray();

        var decryptedData = PgpSamples.PrivateKey.Decrypt(message);

        decryptedData.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, 100, 4096)]
    [InlineData(PgpProfile.Proton, 256_000, 4096)]
    [InlineData(PgpProfile.ProtonAead, 100, 4096)]
    [InlineData(PgpProfile.ProtonAead, 256_000, 4096)]
    public async Task ReadAsync_EncryptsWithV6Key(PgpProfile profile, int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        await using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, profile: profile);

        var readBuffer = new byte[readBufferSize].AsMemory();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = await stream.ReadAsync(readBuffer, CancellationToken.None);
            encryptedDataStream.Write(readBuffer.Span[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = encryptedDataStream.ToArray();

        var decryptedData = PgpSamples.PrivateKeyV6.Decrypt(message);

        decryptedData.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 2)]
    [InlineData(1, 16)]
    [InlineData(1, 4096)]
    [InlineData(2, 1)]
    [InlineData(2, 2)]
    [InlineData(2, 16)]
    [InlineData(2, 4096)]
    [InlineData(100, 1)]
    [InlineData(100, 2)]
    [InlineData(100, 16)]
    [InlineData(100, 4096)]
    [InlineData(256_000, 1)]
    [InlineData(256_000, 2)]
    [InlineData(256_000, 16)]
    [InlineData(256_000, 4096)]
    public void Read_EncryptsWithArmor(int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey, PgpEncoding.AsciiArmor);

        var readBuffer = new byte[readBufferSize].AsSpan();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = stream.Read(readBuffer);
            encryptedDataStream.Write(readBuffer[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = Encoding.UTF8.GetString(encryptedDataStream.ToArray());

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        message.Should().EndWith("-----END PGP MESSAGE-----");
    }

    [Theory]
    [InlineData(PgpProfile.Proton, 100, 4096)]
    [InlineData(PgpProfile.Proton, 256_000, 4096)]
    [InlineData(PgpProfile.ProtonAead, 100, 4096)]
    [InlineData(PgpProfile.ProtonAead, 256_000, 4096)]
    public void Read_EncryptsWithArmor_WithV6Key(PgpProfile profile, int length, int readBufferSize)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, PgpEncoding.AsciiArmor, profile: profile);

        var readBuffer = new byte[readBufferSize].AsSpan();
        var encryptedDataStream = new MemoryStream();
        int bytesRead;

        // Act
        do
        {
            bytesRead = stream.Read(readBuffer);
            encryptedDataStream.Write(readBuffer[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        var message = Encoding.UTF8.GetString(encryptedDataStream.ToArray());

        message.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        message.Should().EndWith("-----END PGP MESSAGE-----");

        // Verify can be decrypted
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var decryptedData = PgpSamples.PrivateKeyV6.Decrypt(messageBytes, PgpEncoding.AsciiArmor);
        decryptedData.Should().Equal(plainData);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void OpenSplitRead_EncryptsWithV6Key(PgpProfile profile)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(1024);
        using var inputStream = new MemoryStream(plainData);
        using var dataPacketStream = new MemoryStream();
        using var keyPacketStream = new MemoryStream();
        using var stream = PgpEncryptingStream.OpenSplitRead(inputStream, keyPacketStream, PgpSamples.PublicKeyV6, profile: profile);

        var readBuffer = new byte[4096].AsSpan();
        int bytesRead;

        // Act
        do
        {
            bytesRead = stream.Read(readBuffer);
            dataPacketStream.Write(readBuffer[..bytesRead]);
        } while (bytesRead > 0);

        // Assert
        dataPacketStream.Length.Should().BePositive();
        keyPacketStream.Length.Should().BePositive();

        // Verify the split packets can be decrypted when combined
        var combinedMessage = new byte[keyPacketStream.Length + dataPacketStream.Length];
        keyPacketStream.Seek(0, SeekOrigin.Begin);
        dataPacketStream.Seek(0, SeekOrigin.Begin);
        keyPacketStream.Read(combinedMessage, 0, (int)keyPacketStream.Length);
        dataPacketStream.Read(combinedMessage, (int)keyPacketStream.Length, (int)dataPacketStream.Length);

        var decryptedData = PgpSamples.PrivateKeyV6.Decrypt(combinedMessage);
        decryptedData.Should().Equal(plainData);
    }
}
