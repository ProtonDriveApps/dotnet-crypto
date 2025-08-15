namespace Proton.Cryptography.Tests;

public class AsciiStreamTest
{
    [Theory]
    [InlineData("")]
    [InlineData("\u263a")]
    [InlineData("abc")]
    [InlineData("áà")]
    [InlineData("\ud83d\ude00")]
    public void Read_ReturnsCorrectNumberOfBytes(string text)
    {
        // Arrange
        Span<byte> buffer = stackalloc byte[text.Length * 2];
        using var stream = new AsciiStream(text);

        // Act
        var numberOfBytesRead = stream.Read(buffer);

        // Assert
        numberOfBytesRead.Should().Be(text.Length);
    }
}
