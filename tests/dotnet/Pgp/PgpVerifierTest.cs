namespace Proton.Cryptography.Tests.Pgp;

public class PgpVerifierTest
{
    [Theory]
    [MemberData(nameof(VerificationTestData.AttachedSignatures), MemberType = typeof(VerificationTestData))]
    public void Verify_ReturnsExpectedVerificationStatus_WhenSignatureIsAttached(Func<byte[]> message, PgpVerificationStatus expectedStatus)
    {
        // Act
        using var verificationResult = PgpVerifier.Verify(message.Invoke(), PgpSamples.UnlockedPrivateKey, PgpEncoding.AsciiArmor);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [MemberData(nameof(VerificationTestData.DetachedPlainSignatures), MemberType = typeof(VerificationTestData))]
    public void Verify_ReturnsExpectedVerificationStatus_WhenSignatureIsDetached(
        Func<byte[]> signature,
        PgpEncoding encoding,
        PgpVerificationStatus expectedStatus)
    {
        // Act
        using var verificationResult = PgpVerifier.Verify(PgpSamples.PlainText, signature.Invoke(), PgpSamples.PublicKey, encoding);

        // Assert
        verificationResult.Status.Should().Be(expectedStatus);
    }
}
