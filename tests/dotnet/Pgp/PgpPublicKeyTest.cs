namespace Proton.Cryptography.Tests.Pgp;

public sealed class PgpPublicKeyTest
{
    [Fact]
    public void Export_Throws_WhenHandleIsInvalid()
    {
        // Arrange
        var publicKey = default(PgpPublicKey);

        // Act
        var act = publicKey.Export;

        // Assert
        act.Invoking(x => x.Invoke(Stream.Null, default)).Should().Throw<Exception>();
    }
}
