namespace Proton.Cryptography.Tests.Srp;

public sealed class SrpClientTest
{
    [Fact]
    public void DeriveVerifier_Succeeds()
    {
        // Arrange
        var modulusVerificationKey = SrpClient.GetDefaultModulusVerificationKey();

        using var client = SrpClient.Create(
            SrpSamples.Username,
            SrpSamples.Password,
            SrpSamples.Salt,
            SrpSamples.SignedModulus,
            modulusVerificationKey);

        // Act
        var verifier = client.DeriveVerifier(SrpSamples.BitLength);

        // Assert
        verifier.Should().Equal(SrpSamples.Verifier);
    }

    [Fact]
    public void HashPassword_Succeeds()
    {
        // Act
        var password = SrpClient.HashPassword(SrpSamples.Password, SrpSamples.PasswordHashingSalt);

        // Assert
        password.Should().Equal(SrpSamples.DerivedPassword.ToArray());
    }
}
