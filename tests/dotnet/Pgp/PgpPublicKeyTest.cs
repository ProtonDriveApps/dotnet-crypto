namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPublicKeyTest
{
    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var publicKey = default(PgpPublicKey);

        // Act
        var act = () => publicKey.Export(Stream.Null, default);

        // Assert
        act.Should().Throw<Exception>();
    }
}
