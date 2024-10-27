namespace Proton.Cryptography.Pgp;

internal record struct PgpDecryptionResult(ArraySegment<byte> Output, PgpVerificationResult VerificationResult);
