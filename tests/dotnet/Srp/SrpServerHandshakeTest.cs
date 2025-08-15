namespace Proton.Cryptography.Tests.Srp;

public sealed class SrpServerHandshakeTest
{
    [Fact]
    public void Create_Succeeds()
    {
        // Act
        var act = () =>
        {
            using var sh = SrpServerHandshake.Generate(SrpSamples.Modulus, SrpSamples.Verifier, SrpSamples.ServerSecret, SrpSamples.BitLength);
        };

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void TryComputeSharedKey_ProvidesCorrectProof()
    {
        // Arrange
        using var serverHandshake = SrpServerHandshake.Generate(SrpSamples.Modulus, SrpSamples.Verifier, SrpSamples.ServerSecret, SrpSamples.BitLength);

        // Act
        var isSuccess = serverHandshake.TryComputeSharedKey(SrpSamples.ClientProof, SrpSamples.ClientEphemeral, out var response);

        // Assert
        isSuccess.Should().BeTrue();
        response!.Should().Equal(SrpSamples.ServerProof);
    }
}
