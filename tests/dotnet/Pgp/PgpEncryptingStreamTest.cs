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

        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
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

        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
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

        signature.ShouldStartWith("-----BEGIN PGP SIGNATURE-----");
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
        dataPacketStream.Length.ShouldBePositive();
        keyPacketStream.Length.ShouldBePositive();
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
        dataPacketOutputStream.Length.ShouldBePositive();
        keyPacketOutputStream.Length.ShouldBePositive();
        signatureOutputStream.Length.ShouldBePositive();
    }
}
