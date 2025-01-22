namespace Proton.Cryptography.Tests.Pgp;

public class PgpVerifierTest
{
    [Theory]
    [InlineData(PgpSamples.ArmoredSignedMessage, PgpVerificationStatus.Ok)]
    [InlineData(PgpSamples.KeyBasedArmoredMessageWithInvalidSignature, PgpVerificationStatus.Failed)]
    [InlineData(PgpSamples.KeyBasedArmoredMessageWithNonMatchingSignature, PgpVerificationStatus.NoVerifier)]
    [InlineData(PgpSamples.KeyBasedArmoredUnsignedMessage, PgpVerificationStatus.NotSigned)]
    public void Verify_ReturnsExpectedVerificationStatus_WhenSignatureIsAttached(string message, PgpVerificationStatus expectedStatus)
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(message);

        // Act
        using var verificationResult = PgpVerifier.Verify(input, PgpSamples.PrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        verificationResult.Status.ShouldBe(expectedStatus);
    }

    [Theory]
    [InlineData(PgpSamples.Signature, PgpEncoding.None, PgpVerificationStatus.Ok)]
    [InlineData(PgpSamples.ArmoredSignature, PgpEncoding.AsciiArmor, PgpVerificationStatus.Ok)]
    [InlineData(PgpSamples.InvalidSignature, PgpEncoding.None, PgpVerificationStatus.Failed)]
    [InlineData(PgpSamples.ArmoredInvalidSignature, PgpEncoding.AsciiArmor, PgpVerificationStatus.Failed)]
    public void Verify_ReturnsExpectedVerificationStatus_WhenSignatureIsDetached(string signature, PgpEncoding encoding, PgpVerificationStatus expectedStatus)
    {
        // Arrange
        var input = Encoding.ASCII.GetBytes(PgpSamples.PlainText);
        var detachedSignature = encoding == PgpEncoding.AsciiArmor ? Encoding.ASCII.GetBytes(signature) : Convert.FromBase64String(signature);

        // Act
        using var verificationResult = PgpVerifier.Verify(input, detachedSignature, PgpSamples.PublicKey, encoding);

        // Assert
        verificationResult.Status.ShouldBe(expectedStatus);
    }
}
