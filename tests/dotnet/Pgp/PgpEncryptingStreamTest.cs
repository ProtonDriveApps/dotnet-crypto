using System.Security.Cryptography;

namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpEncryptingStreamTest
{
    private const int Timeout = 500;

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessage(PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey, encoding);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.Decrypt(outputStream.GetSpan(), encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessageWithAttachedSignature_WhenSigningKeysProvided(PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey, PgpSamples.UnlockedPrivateKey, encoding);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.DecryptAndVerify(outputStream.GetSpan(), PgpSamples.PublicKey, out var verificationResult, encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpEncoding.None)]
    [InlineData(PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessageWithDetachedSignature_WhenOutputSignatureStreamProvided(PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(
            inputStream,
            signatureOutputStream,
            PgpSamples.PublicKey,
            PgpSamples.UnlockedPrivateKey,
            encoding);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);
        PgpEncodingAssertions.ShouldMatchEncoding(signatureOutputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.DecryptAndVerify(
            outputStream.GetSpan(),
            signatureOutputStream.GetSpan(),
            PgpSamples.PublicKey,
            out var verificationResult,
            encoding,
            encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Fact]
    public void Read_ProducesValidMessageWithDetachedKeyPackets_WhenKeyPacketOutputStreamProvided()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplitRead(inputStream, keyPacketOutputStream, PgpSamples.PublicKey);

        // Act
        stream.ReadAll(dataPacketOutputStream);

        // Assert
        var messageBytes = new byte[keyPacketOutputStream.Length + dataPacketOutputStream.Length].AsSpan();
        keyPacketOutputStream.GetSpan().CopyTo(messageBytes);
        dataPacketOutputStream.GetSpan().CopyTo(messageBytes[(int)keyPacketOutputStream.Length..]);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.Decrypt(messageBytes);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Fact]
    public void Read_ProducesValidMessageWithDetachedSignatureAndKeyPackets_WhenSignatureAndKeyPacketStreamsProvided()
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplitRead(
            inputStream,
            keyPacketOutputStream,
            signatureOutputStream,
            PgpSamples.PublicKey,
            PgpSamples.UnlockedPrivateKey);

        // Act
        stream.ReadAll(dataPacketOutputStream);

        // Assert
        var messageBytes = new byte[keyPacketOutputStream.Length + dataPacketOutputStream.Length].AsSpan();
        keyPacketOutputStream.GetSpan().CopyTo(messageBytes);
        dataPacketOutputStream.GetSpan().CopyTo(messageBytes[(int)keyPacketOutputStream.Length..]);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.DecryptAndVerify(
            messageBytes,
            signatureOutputStream.GetSpan(),
            PgpSamples.PublicKey,
            out var verificationResult);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessage_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, encoding, profile: profile);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.Decrypt(outputStream.GetSpan(), encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessageWithAttachedSignature_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, PgpSamples.UnlockedPrivateKey, encoding, profile: profile);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(
            outputStream.GetSpan(),
            PgpSamples.PublicKey,
            out var verificationResult,
            encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessageWithDetachedSignature_WhenUsingProfileWithV6Key(PgpProfile profile, PgpEncoding encoding)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var outputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(
            inputStream,
            signatureOutputStream,
            PgpSamples.PublicKeyV6,
            PgpSamples.UnlockedPrivateKeyV6,
            encoding,
            profile: profile);

        // Act
        stream.ReadAll(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);
        PgpEncodingAssertions.ShouldMatchEncoding(signatureOutputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(
            outputStream.GetSpan(),
            signatureOutputStream.GetSpan(),
            PgpSamples.PublicKeyV6,
            out var verificationResult,
            encoding,
            encoding);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Read_ProducesValidMessageWithDetachedKeyPackets_WhenUsingProfileWithV6Key(PgpProfile profile)
    {
        // Arrange=
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplitRead(inputStream, keyPacketOutputStream, PgpSamples.PublicKeyV6, profile: profile);

        // Act
        stream.ReadAll(dataPacketOutputStream);

        // Assert
        var messageBytes = new byte[keyPacketOutputStream.Length + dataPacketOutputStream.Length].AsSpan();
        keyPacketOutputStream.GetSpan().CopyTo(messageBytes);
        dataPacketOutputStream.GetSpan().CopyTo(messageBytes[(int)keyPacketOutputStream.Length..]);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.Decrypt(messageBytes);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [InlineData(PgpProfile.Proton)]
    [InlineData(PgpProfile.ProtonAead)]
    public void Read_ProducesValidMessageWithDetachedSignatureAndKeyPackets_WhenUsingProfileWithV6Key(PgpProfile profile)
    {
        // Arrange
        using var inputStream = new MemoryStream(PgpSamples.PlainText, writable: false);
        using var dataPacketOutputStream = new MemoryStream();
        using var keyPacketOutputStream = new MemoryStream();
        using var signatureOutputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenSplitRead(
            inputStream,
            keyPacketOutputStream,
            signatureOutputStream,
            PgpSamples.PublicKeyV6,
            PgpSamples.UnlockedPrivateKeyV6,
            profile: profile);

        // Act
        stream.ReadAll(dataPacketOutputStream);

        // Assert
        var messageBytes = new byte[keyPacketOutputStream.Length + dataPacketOutputStream.Length].AsSpan();
        keyPacketOutputStream.GetSpan().CopyTo(messageBytes);
        dataPacketOutputStream.GetSpan().CopyTo(messageBytes[(int)keyPacketOutputStream.Length..]);

        var decryptedBytes = PgpSamples.UnlockedPrivateKeyV6.DecryptAndVerify(
            messageBytes,
            signatureOutputStream.GetSpan(),
            PgpSamples.PublicKeyV6,
            out var verificationResult);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
        verificationResult.Status.Should().Be(PgpVerificationStatus.Ok);
    }

    [Theory(Timeout = Timeout)]
    [InlineData(1, 1, PgpEncoding.None)]
    [InlineData(1, 2, PgpEncoding.None)]
    [InlineData(1, 4096, PgpEncoding.None)]
    [InlineData(2, 1, PgpEncoding.None)]
    [InlineData(2, 2, PgpEncoding.None)]
    [InlineData(2, 4096, PgpEncoding.None)]
    [InlineData(100, 1, PgpEncoding.None)]
    [InlineData(100, 2, PgpEncoding.None)]
    [InlineData(100, 4096, PgpEncoding.None)]
    [InlineData(100_000, 1, PgpEncoding.None)]
    [InlineData(100_000, 2, PgpEncoding.None)]
    [InlineData(100_000, 4096, PgpEncoding.None)]
    [InlineData(1, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(100, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(100_000, 4096, PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessage_ForMultiplePlaintextAndBufferSizes(int length, int readBufferSize, PgpEncoding encoding)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData, 0, plainData.Length, false, true);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey, encoding);

        // Act
        stream.ReadAll(outputStream, readBufferSize);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedBytes = PgpSamples.UnlockedPrivateKey.Decrypt(outputStream.GetSpan(), encoding);

        decryptedBytes.Should().Equal(plainData);
    }

    [Theory(Timeout = Timeout)]
    [InlineData(PgpProfile.Proton, 100, 1, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, 100, 4096, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, 100_000, 4096, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, 100, 1, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, 100, 4096, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, 100_000, 4096, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, 100, 1, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.Proton, 100, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.Proton, 100_000, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, 100, 1, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, 100, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, 100_000, 4096, PgpEncoding.AsciiArmor)]
    public void Read_ProducesValidMessage_ForMultiplePlaintextAndBufferSizes_WhenUsingProfileAndV6Key(
        PgpProfile profile,
        int length,
        int readBufferSize,
        PgpEncoding encoding)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var outputStream = new MemoryStream();

        using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, encoding, profile: profile);

        // Act
        stream.ReadAll(outputStream, readBufferSize);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedData = PgpSamples.UnlockedPrivateKeyV6.Decrypt(outputStream.GetSpan(), encoding);

        decryptedData.Should().Equal(plainData);
    }

    [Theory(Timeout = Timeout)]
    [InlineData(1, 1, PgpEncoding.None)]
    [InlineData(1, 2, PgpEncoding.None)]
    [InlineData(1, 4096, PgpEncoding.None)]
    [InlineData(2, 1, PgpEncoding.None)]
    [InlineData(2, 2, PgpEncoding.None)]
    [InlineData(2, 4096, PgpEncoding.None)]
    [InlineData(100, 1, PgpEncoding.None)]
    [InlineData(100, 2, PgpEncoding.None)]
    [InlineData(100, 4096, PgpEncoding.None)]
    [InlineData(100_000, 1, PgpEncoding.None)]
    [InlineData(100_000, 2, PgpEncoding.None)]
    [InlineData(100_000, 4096, PgpEncoding.None)]
    [InlineData(1, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(100, 4096, PgpEncoding.AsciiArmor)]
    [InlineData(100_000, 4096, PgpEncoding.AsciiArmor)]
    public async Task ReadAsync_ProducesValidMessage_ForMultiplePlaintextAndBufferSizes(int length, int readBufferSize, PgpEncoding encoding)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var outputStream = new MemoryStream();

        await using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKey, encoding);

        // Act
        await stream.ReadAllAsync(outputStream, readBufferSize);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedData = PgpSamples.UnlockedPrivateKey.Decrypt(outputStream.GetSpan(), encoding);

        decryptedData.Should().Equal(plainData);
    }

    [Theory(Timeout = Timeout)]
    [InlineData(PgpProfile.Proton, 100, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, 100_000, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, 100, PgpEncoding.None)]
    [InlineData(PgpProfile.ProtonAead, 100_000, PgpEncoding.None)]
    [InlineData(PgpProfile.Proton, 100, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.Proton, 100_000, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, 100, PgpEncoding.AsciiArmor)]
    [InlineData(PgpProfile.ProtonAead, 100_000, PgpEncoding.AsciiArmor)]
    public async Task ReadAsync_ProducesValidMessage_ForMultiplePlaintextSizes_WhenUsingProfileAndV6Key(PgpProfile profile, int length, PgpEncoding encoding)
    {
        // Arrange
        var plainData = RandomNumberGenerator.GetBytes(length);
        using var inputStream = new MemoryStream(plainData);
        using var outputStream = new MemoryStream();

        await using var stream = PgpEncryptingStream.OpenRead(inputStream, PgpSamples.PublicKeyV6, encoding, profile: profile);

        // Act
        await stream.ReadAllAsync(outputStream);

        // Assert
        PgpEncodingAssertions.ShouldMatchEncoding(outputStream, encoding);

        var decryptedData = PgpSamples.UnlockedPrivateKeyV6.Decrypt(outputStream.GetSpan(), encoding);

        decryptedData.Should().Equal(plainData);
    }
}
