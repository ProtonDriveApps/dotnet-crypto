namespace Proton.Cryptography.Tests.Pgp;

internal static class VerificationTestData
{
    public static IEnumerable<TheoryDataRow<Func<byte[]>, PgpVerificationStatus>> InlineSignatures()
    {
        yield return (() => PgpSamples.ArmoredInlineSignedMessage, PgpVerificationStatus.Ok);
        yield return (() => PgpSamples.ArmoredInlineMessageWithInvalidSignature, PgpVerificationStatus.Failed);
        yield return (() => PgpSamples.ArmoredInlineMessageWithNonMatchingSignature, PgpVerificationStatus.NoVerifier);
        yield return (() => PgpSamples.KeyBasedArmoredUnsignedMessage, PgpVerificationStatus.NotSigned);
    }

    public static IEnumerable<TheoryDataRow<Func<byte[]>, PgpEncoding, EncryptionState, PgpVerificationStatus>> DetachedSignatures()
    {
        foreach (var row in DetachedPlainSignatures())
        {
            var (getSignature, encoding, verificationStatus) = row.Data;
            yield return (getSignature, encoding, EncryptionState.Plain, verificationStatus);
        }

        yield return (() => PgpSamples.ArmoredEncryptedSignature, PgpEncoding.AsciiArmor, EncryptionState.Encrypted, PgpVerificationStatus.Ok);
    }

    public static IEnumerable<TheoryDataRow<Func<byte[]>, PgpEncoding, PgpVerificationStatus>> DetachedPlainSignatures()
    {
        yield return (() => PgpSamples.Signature, PgpEncoding.None, PgpVerificationStatus.Ok);
        yield return (() => PgpSamples.ArmoredSignature, PgpEncoding.AsciiArmor, PgpVerificationStatus.Ok);
        yield return (() => PgpSamples.ArmoredInvalidSignature, PgpEncoding.AsciiArmor, PgpVerificationStatus.Failed);
        yield return (() => PgpSamples.InvalidSignature, PgpEncoding.None, PgpVerificationStatus.Failed);
    }
}
