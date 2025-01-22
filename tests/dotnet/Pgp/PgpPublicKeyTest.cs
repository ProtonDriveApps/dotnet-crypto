namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPublicKeyTest
{
    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var publicKey = default(PgpPublicKey);

        // Act
        var act = new Action(() => publicKey.Export(Stream.Null, default));

        // Assert
        act.ShouldThrow<Exception>();
    }
}
