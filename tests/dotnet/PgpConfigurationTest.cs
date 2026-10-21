namespace Proton.Cryptography.Tests.Pgp;

/// <summary>
/// Tests that the buffer size reported by <see cref="PgpConfiguration.GetAeadDecryptionMinimumInputLength"/>
/// is large enough to decrypt the start of an AEAD message.
///
/// A consumer that only needs to peek at the beginning of an AEAD-encrypted message (for example, a
/// block verifier that checks a freshly encrypted block against its session key) decrypts just the
/// first <see cref="PgpConfiguration.GetAeadDecryptionMinimumInputLength"/> bytes and reads a short
/// plaintext prefix. For that read to succeed the budget must hold the packet header plus one full
/// AEAD chunk.
///
/// rust-crypto reports end-of-file to the decryptor as soon as the input stream returns zero bytes
/// (see the reader callback that maps a zero-length read to EOF). If the budget ends mid-chunk, that
/// EOF lands before a full chunk is available and rust-crypto throws an "expecting more data" error,
/// whereas go-crypto tolerated it. Sizing the budget to <c>chunk length + overhead</c> fixes it.
/// </summary>
public sealed class PgpConfigurationTest
{
    // The number of plaintext bytes a prefix-only consumer reads back to verify the start of the
    // message. Small on purpose: it only requires the first AEAD chunk to be decryptable.
    private const int PlaintextPrefixLength = 16;

    private const int ChunkLength64KiB = 1 << 16;
    private const int ChunkLength128KiB = 1 << 17;

    private const int MessageSize256KiB = 256 * 1024;
    private const int MessageSize512KiB = 512 * 1024;
    private const int MessageSize4MiB = 4 * 1024 * 1024;

    // Generated once when the class is loaded and reused by every case, so a plaintext is never
    // rebuilt per run. Cases select one by size through GetPlaintext.
    private static readonly byte[] Plaintext256KiB = CreateIncompressiblePlaintext(MessageSize256KiB);
    private static readonly byte[] Plaintext512KiB = CreateIncompressiblePlaintext(MessageSize512KiB);
    private static readonly byte[] Plaintext4MiB = CreateIncompressiblePlaintext(MessageSize4MiB);

    public static TheoryData<int, int, int> BufferReadScenarios()
    {
        // Every message exceeds GetAeadDecryptionMinimumInputLength for both chunk lengths, so each
        // case produces at least one full chunk followed by more data - exactly the situation where a
        // budget that ended mid-chunk would trigger "expecting more data".
        var chunkLengths = new[] { ChunkLength64KiB, ChunkLength128KiB };
        var messageSizes = new[] { MessageSize256KiB, MessageSize512KiB, MessageSize4MiB };

        // Sizes of the partial reads to test compatibility with different PGP length encodings.
        var partialReadSizes = new[] { 100, 5_000, 20_000, 5_000_000 };

        var data = new TheoryData<int, int, int>();

        foreach (var chunkLength in chunkLengths)
        {
            foreach (var messageSize in messageSizes)
            {
                foreach (var partialReadSize in partialReadSizes)
                {
                    data.Add(chunkLength, messageSize, partialReadSize);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(BufferReadScenarios))]
    public void MinimumInputLength_YieldsDecryptablePrefix_WhenFedInPartialReads(int chunkLength, int messageSize, int partialReadSize)
    {
        // Arrange
        var plaintext = GetPlaintext(messageSize);

        using var sessionKey = PgpSessionKey.GenerateForAead();

        var encryptedMessage = EncryptWithAead(sessionKey, plaintext, chunkLength);

        // Hand the decryptor only the first GetAeadDecryptionMinimumInputLength bytes of the message
        // (clamped to the message length for messages smaller than that budget). This budget must hold
        // the header plus one full AEAD chunk so the prefix can be decrypted.
        var bufferLength = Math.Min(PgpConfiguration.GetAeadDecryptionMinimumInputLength(chunkLength), encryptedMessage.Length);

        var verificationBuffer = encryptedMessage.AsMemory(0, bufferLength);

        // Act
        using var input = new PartialReadStream(verificationBuffer, partialReadSize);
        using var decryptingStream = sessionKey.OpenDecryptingStream(input);

        var decryptedPrefix = new byte[PlaintextPrefixLength];
        var bytesRead = decryptingStream.ReadAtLeast(
            decryptedPrefix,
            decryptedPrefix.Length,
            throwOnEndOfStream: false);

        // Assert
        bytesRead.Should().Be(
            PlaintextPrefixLength,
            "the header + one full chunk buffer must be enough to decrypt the verification prefix");

        decryptedPrefix.Should().Equal(plaintext[..PlaintextPrefixLength]);
    }

    private static byte[] GetPlaintext(int messageSize) => messageSize switch
    {
        MessageSize256KiB => Plaintext256KiB,
        MessageSize512KiB => Plaintext512KiB,
        MessageSize4MiB => Plaintext4MiB,
        _ => throw new ArgumentOutOfRangeException(nameof(messageSize), messageSize, "No static plaintext for this size."),
    };

    private static byte[] EncryptWithAead(PgpSessionKey sessionKey, byte[] plaintext, int chunkLength)
    {
        // AEAD profile with the given streaming chunk length and no compression, matching how a
        // streaming content producer encrypts a block.
        using var plaintextStream = new MemoryStream(plaintext, writable: false);
        using var encryptingStream = sessionKey.OpenEncryptingReadStream(
            plaintextStream,
            profile: PgpProfile.ProtonAead,
            aeadStreamingChunkLength: chunkLength);
        using var encryptedStream = new MemoryStream();

        encryptingStream.ReadAll(encryptedStream);

        return encryptedStream.ToArray();
    }

    private static byte[] CreateIncompressiblePlaintext(int size)
    {
        // Deterministic but incompressible content, so the AEAD chunking reflects the real plaintext
        // chunk boundaries even if compression is ever enabled. Generated with a small xorshift PRNG
        // (seed derived from the size) to keep each case reproducible without a framework RNG.
        var plaintext = new byte[size];
        var state = (uint)size + 0x9E3779B9u;

        for (var i = 0; i < size; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            plaintext[i] = (byte)state;
        }

        return plaintext;
    }

    /// <summary>
    /// A read-only stream that exposes its backing buffer through small partial reads, so the decryptor
    /// is driven through the incremental delivery a real streaming source would produce.
    /// <see cref="Read(Span{byte})"/> never returns more than <c>maxBytesPerRead</c> bytes and only
    /// signals end-of-stream once the buffer is exhausted.
    /// </summary>
    private sealed class PartialReadStream(ReadOnlyMemory<byte> data, int maxBytesPerRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => data.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(Span<byte> buffer)
        {
            var remaining = data.Length - _position;
            if (remaining <= 0)
            {
                return 0;
            }

            var count = Math.Min(Math.Min(maxBytesPerRead, buffer.Length), remaining);

            data.Span.Slice(_position, count).CopyTo(buffer);
            _position += count;

            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
