namespace Proton.Cryptography.Tests.Srp;

public sealed class SrpClientHandshakeTest
{
    [Fact]
    public void TryComputeSharedKey_AcceptsCorrectProof()
    {
        // Arrange
        var modulusVerificationKey = SrpClient.GetDefaultModulusVerificationKey();

        using var client = SrpClient.Create(
            SrpSamples.Username,
            SrpSamples.Password,
            SrpSamples.Salt,
            SrpSamples.SignedModulus,
            modulusVerificationKey);

        using var serverHandshake = SrpServerHandshake.Generate(SrpSamples.Modulus, SrpSamples.Verifier, SrpSamples.ServerSecret, SrpSamples.BitLength);

        using var clientHandshake = client.ComputeHandshake(serverHandshake.Ephemeral, SrpSamples.BitLength);

        serverHandshake.TryComputeSharedKey(clientHandshake.Proof, clientHandshake.Ephemeral, out var serverProof);

        // Act
        var isSuccess = clientHandshake.TryComputeSharedKey(serverProof!);

        // Assert
        isSuccess.Should().BeTrue();
    }
}
