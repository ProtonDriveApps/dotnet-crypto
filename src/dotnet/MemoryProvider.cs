using System.Buffers;
using Proton.Cryptography.Pgp;

namespace Proton.Cryptography;

internal static class MemoryProvider
{
    private const int MaxStackBufferSize = 0x100;
    private const int MinArmorHeaderPlusFooterLength = 54;

    // Smallest number of non-data characters in any block the native library accepts: "-----BEGIN PUBLIC KEY-----" and
    // "-----END PUBLIC KEY-----" (50), plus the line break after the begin line and the blank line before the data (2).
    // Unlike MinArmorHeaderPlusFooterLength, which feeds an estimate, this must never exceed the real overhead.
    private const int MinArmorNonDataLength = 52;

    private const int MaxArmorHeaderPlusFooterLength = 74;
    private const int GenerousArmorVersionAndCommentLength = 90;
    private const int ArmorBytesPerNewline = 48;
    private const int ExpectedKeyPacketLength = 96;
    private const int ExpectedDataPacketOverhead = 60;
    private const int ExpectedSignatureLength = 190;

    public static bool GetHeapMemoryIfTooLargeForStack(int size, out Memory<byte> heapMemory, out IMemoryOwner<byte>? heapMemoryOwner)
    {
        if (size <= MaxStackBufferSize)
        {
            heapMemory = default;
            heapMemoryOwner = null;
            return false;
        }

        if (size > MemoryPool<byte>.Shared.MaxBufferSize)
        {
            heapMemoryOwner = null;
            heapMemory = new byte[size];
        }
        else
        {
            heapMemoryOwner = MemoryPool<byte>.Shared.Rent(size);
            heapMemory = heapMemoryOwner.Memory;
        }

        return true;
    }

    public static MemoryStream GetMemoryStreamForMessage(int plaintextLength, int numberOfEncryptionKeys, int numberOfSigningKeys, PgpEncoding encoding)
    {
        return new MemoryStream(EstimateMessageLength(plaintextLength, numberOfEncryptionKeys, numberOfSigningKeys, encoding));
    }

    public static MemoryStream GetMemoryStreamForDecodedMessage(int armoredLength)
    {
        return new MemoryStream(EstimateDecodedLength(armoredLength));
    }

    public static MemoryStream GetMemoryStreamForArmoredMessage(int unarmoredLength)
    {
        return new MemoryStream(EstimateEncodedLength(unarmoredLength, PgpEncoding.AsciiArmor));
    }

    public static MemoryStream GetMemoryStreamForKeyPackets(int numberOfEncryptionKeys)
    {
        return new MemoryStream(EstimateKeyPacketsLength(numberOfEncryptionKeys));
    }

    public static MemoryStream GetMemoryStreamForSignature(int numberOfSigningKeys, PgpEncoding encoding)
    {
        return new MemoryStream(EstimateSignatureLength(numberOfSigningKeys, encoding));
    }

    public static MemoryStream GetMemoryStreamForPlaintext(int messageLength, PgpEncoding encoding)
    {
        return new MemoryStream(EstimatePlaintextLength(messageLength, encoding));
    }

    public static int EstimateMessageLength(int plaintextLength, int numberOfEncryptionKeys, int numberOfSigningKeys, PgpEncoding encoding)
    {
        var keyPacketsLength = EstimateKeyPacketsLength(numberOfEncryptionKeys);
        var dataPacketLength = EstimateDataPacketLength(plaintextLength);
        var signatureLength = EstimateSignatureLength(numberOfSigningKeys, PgpEncoding.None);
        var binaryLength = keyPacketsLength + dataPacketLength + signatureLength;

        return EstimateEncodedLength(binaryLength, encoding);
    }

    public static int EstimateKeyPacketsLength(int numberOfEncryptionKeys)
    {
        return numberOfEncryptionKeys * ExpectedKeyPacketLength;
    }

    public static long EstimateDataPacketLength(int plaintextLength)
    {
        return ((plaintextLength * 110L) / 100L) + ExpectedDataPacketOverhead;
    }

    public static int EstimateSignatureLength(int numberOfSigningKeys, PgpEncoding encoding)
    {
        var binaryLength = numberOfSigningKeys * ExpectedSignatureLength;

        return EstimateEncodedLength(binaryLength, encoding);
    }

    public static int EstimatePlaintextLength(int messageLength, PgpEncoding encoding)
    {
        // In case the message contains compressed data, this can largely underestimate. There's not much that can be done about it.
        return encoding == PgpEncoding.None ? messageLength : (Math.Max(0, messageLength - MinArmorHeaderPlusFooterLength) * 3) / 4;
    }

    public static int EstimateEncodedLength(long originalLength, PgpEncoding encoding)
    {
        return (int)(encoding == PgpEncoding.AsciiArmor
            ? ((originalLength * 4L) / 3L) + MaxArmorHeaderPlusFooterLength + GenerousArmorVersionAndCommentLength + (originalLength / ArmorBytesPerNewline)
            : originalLength);
    }

    public static int EstimateDecodedLength(long armoredLength)
    {
        // Every 4 base64 characters decode to at most 3 bytes, so this is an upper bound for any accepted armored block.
        var maxBase64Length = Math.Max(0, armoredLength - MinArmorNonDataLength);

        return (int)((maxBase64Length * 3L) / 4L);
    }
}
