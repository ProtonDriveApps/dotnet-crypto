using System.Security.Cryptography;

namespace Proton.Cryptography.Tests;

public sealed class AesGcmDecrypterTest
{
    [Fact]
    public void Decrypt_ReturnsCorrectNumberOfBytes()
    {
        // Arrange
        var secret = "hello"u8;
        var key = RandomNumberGenerator.GetBytes(32);
        var blob = Encrypt(key, secret, GetAssociatedData());
        var destination = new byte[AesGcmDecrypter.GetPlaintextLength(blob.Length)];

        // Act
        var bytesWritten = AesGcmDecrypter.Decrypt(key, blob, destination, GetAssociatedData());

        // Assert
        bytesWritten.Should().Be(secret.Length);
        destination.Should().Equal(secret.ToArray());
    }

    [Fact]
    public void Decrypt_WithTamperedTag_Throws()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(32);
        var blob = Encrypt(key, "hello"u8, GetAssociatedData());
        var destination = new byte[AesGcmDecrypter.GetPlaintextLength(blob.Length)];

        // Act
        blob[^1] ^= 0x01;

        // Assert
        Assert.Throws<AuthenticationTagMismatchException>(() => AesGcmDecrypter.Decrypt(key, blob, destination, GetAssociatedData()));
    }

    private static ReadOnlySpan<byte> GetAssociatedData() => "fork"u8;

    private static byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        var blob = new byte[AesGcmDecrypter.NonceLength + plaintext.Length + AesGcmDecrypter.TagLength];
        var nonce = blob.AsSpan(0, AesGcmDecrypter.NonceLength);
        var ciphertext = blob.AsSpan(AesGcmDecrypter.NonceLength, plaintext.Length);
        var tag = blob.AsSpan(blob.Length - AesGcmDecrypter.TagLength);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, AesGcmDecrypter.TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return blob;
    }
}
