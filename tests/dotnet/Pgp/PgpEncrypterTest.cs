﻿namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpEncrypterTest
{
    [Fact]
    public void Encrypt_Succeeds()
    {
        // Act
        var messageBytes = PgpEncrypter.Encrypt(Encoding.UTF8.GetBytes(PgpSamples.PlainText), PgpSamples.PublicKey, PgpEncoding.AsciiArmor);

        // Assert
        var message = Encoding.UTF8.GetString(messageBytes);
        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
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
        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
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

        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
        signature.ShouldStartWith("-----BEGIN PGP SIGNATURE-----");
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
        message.ShouldStartWith("-----BEGIN PGP MESSAGE-----");
    }
}
