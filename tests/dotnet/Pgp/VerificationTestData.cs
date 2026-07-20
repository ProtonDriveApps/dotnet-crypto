namespace Proton.Cryptography.Tests.Pgp;

internal static class VerificationTestData
{
    public static IEnumerable<TheoryDataRow<Func<byte[]>, PgpVerificationContext?, PgpVerificationStatus>> EncryptedMessagesWithInlineSignatures()
    {
        yield return (() => PgpSamples.ArmoredEncryptedSignedMessage, null, PgpVerificationStatus.Ok);
        yield return (() => PgpSamples.KeyBasedArmoredEncryptedMessageWithInvalidSignature, null, PgpVerificationStatus.Failed);
        yield return (() => PgpSamples.KeyBasedArmoredEncryptedMessageWithNonMatchingSignature, null, PgpVerificationStatus.NoVerifier);
        yield return (() => PgpSamples.KeyBasedArmoredEncryptedUnsignedMessage, null, PgpVerificationStatus.NotSigned);
        yield return (
            () => PgpSamples.ArmoredEncryptedSignedMessage,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: true),
            PgpVerificationStatus.BadContext);
        yield return (
            () => PgpSamples.ArmoredEncryptedSignedMessage,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: false),
            PgpVerificationStatus.Ok);
        yield return (
            () => PgpSamples.ArmoredEncryptedSignedMessageWithContext,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: true),
            PgpVerificationStatus.Ok);
        yield return (
            () => PgpSamples.ArmoredEncryptedSignedMessageWithContext,
            PgpVerificationContext.Create("unexpected-context", isRequired: true),
            PgpVerificationStatus.BadContext);
    }

    public static IEnumerable<TheoryDataRow<Func<byte[]>, PgpVerificationContext?, PgpVerificationStatus>> PlainMessagesWithInlineSignatures()
    {
        yield return (() => PgpSamples.ArmoredPlainSignedMessage, null, PgpVerificationStatus.Ok);
        yield return (() => PgpSamples.ArmoredPlainMessageWithInvalidSignature, null, PgpVerificationStatus.Failed);
        yield return (() => PgpSamples.ArmoredPlainMessageWithNonMatchingSignature, null, PgpVerificationStatus.NoVerifier);
        yield return (() => PgpSamples.ArmoredPlainUnsignedMessage, null, PgpVerificationStatus.NotSigned);
        yield return (
            () => PgpSamples.ArmoredPlainSignedMessage,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: true),
            PgpVerificationStatus.BadContext);
        yield return (
            () => PgpSamples.ArmoredPlainSignedMessage,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: false),
            PgpVerificationStatus.Ok);
        yield return (
            () => PgpSamples.ArmoredPlainSignedMessageWithContext,
            PgpVerificationContext.Create(PgpSamples.VerificationContext, isRequired: true),
            PgpVerificationStatus.Ok);
        yield return (
            () => PgpSamples.ArmoredPlainSignedMessageWithContext,
            PgpVerificationContext.Create("unexpected-context", isRequired: true),
            PgpVerificationStatus.BadContext);
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
