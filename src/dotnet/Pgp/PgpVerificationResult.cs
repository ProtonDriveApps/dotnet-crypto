using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

public readonly struct PgpVerificationResult : IDisposable
{
    private readonly GoVerificationResult? _goVerificationResult;

    internal PgpVerificationResult(GoVerificationResult goVerificationResult)
    {
        _goVerificationResult = goVerificationResult;
    }

    public PgpVerificationStatus Status => GoVerificationResult.GetVerificationStatus();

    private GoVerificationResult GoVerificationResult => _goVerificationResult ?? throw new InvalidOperationException("Invalid handle");

    public PgpSignatureDetails GetSignatureDetails()
    {
        throw new NotImplementedException();
    }

    public string[] GetAllSignatures()
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        _goVerificationResult?.Dispose();
    }
}
