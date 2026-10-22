namespace Proton.Cryptography.Tests.Pgp;

public class PgpArmorDecoderTest
{
    [Fact]
    public void Read_ProducesDecodedBytes()
    {
        // Arrange
        using var outputStream = new MemoryStream();

        // Act
        PgpArmorDecoder.Decode(PgpSamples.KeyBasedArmoredEncryptedUnsignedMessage, outputStream);

        // Assert
        var decryptedBytes = PgpDecrypter.Decrypt(outputStream.GetSpan(), PgpSamples.UnlockedPrivateKey);

        decryptedBytes.Should().Equal(PgpSamples.PlainText);
    }

    [Theory]
    [MemberData(nameof(ArmoredBlocks))]
    public void Decode_ToSpanOfMaxLengthAfterDecoding_ProducesDecodedBytes(Func<byte[]> getArmoredBlock)
    {
        // Arrange
        var armoredBlock = getArmoredBlock();
        var output = new byte[PgpArmorDecoder.GetMaxLengthAfterDecoding(armoredBlock.Length)];

        // Act
        var numberOfBytesWritten = PgpArmorDecoder.Decode(armoredBlock, output);

        // Assert
        using var expectedOutputStream = new MemoryStream();
        PgpArmorDecoder.Decode(armoredBlock, expectedOutputStream);

        output[..numberOfBytesWritten].Should().Equal(expectedOutputStream.ToArray());
    }

    [Theory]
    [MemberData(nameof(ArmoredBlocks))]
    public void Decode_ToArraySegment_AllocatesOutputBufferOnce(Func<byte[]> getArmoredBlock)
    {
        // Arrange
        var armoredBlock = getArmoredBlock();

        // Act
        var decodedBlock = PgpArmorDecoder.Decode(armoredBlock);

        // Assert
        decodedBlock.Array.Should().NotBeNull().And.HaveCount(PgpArmorDecoder.GetMaxLengthAfterDecoding(armoredBlock.Length));
    }

    public static IEnumerable<TheoryDataRow<Func<byte[]>>> ArmoredBlocks()
    {
        yield return new TheoryDataRow<Func<byte[]>>(() => PgpSamples.ArmoredSignature);
        yield return new TheoryDataRow<Func<byte[]>>(() => PgpSamples.ArmoredPublicKey);
        yield return new TheoryDataRow<Func<byte[]>>(() => PgpSamples.ArmoredLockedPrivateKey);
        yield return new TheoryDataRow<Func<byte[]>>(() => PgpSamples.KeyBasedArmoredEncryptedUnsignedMessage);

        // The smallest overhead the native library accepts, which makes the maximum length exact
        yield return new TheoryDataRow<Func<byte[]>>(() => GetMinimalPublicKeyBlock(300));

        foreach (var length in new[] { 1, 2, 3, 47, 48, 49, 1000, 100_000 })
        {
            foreach (var blockType in Enum.GetValues<PgpBlockType>())
            {
                yield return new TheoryDataRow<Func<byte[]>>(() => PgpArmorEncoder.Encode(GetRandomBytes(length), blockType).ToArray());
            }
        }
    }

    private static byte[] GetMinimalPublicKeyBlock(int dataLength)
    {
        var base64Data = Convert.ToBase64String(GetRandomBytes(dataLength));

        return Encoding.ASCII.GetBytes($"-----BEGIN PUBLIC KEY-----\n\n{base64Data}-----END PUBLIC KEY-----");
    }

    private static byte[] GetRandomBytes(int length)
    {
        var bytes = new byte[length];
        new Random(length).NextBytes(bytes);
        return bytes;
    }
}
