namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct GoPlaintextResult
{
    public bool HasVerificationResult;
    public nint VerificationResultHandle;
#pragma warning disable SA1214 // Readonly fields should appear before non-readonly fields
    // Warning disabled because this field needs to be in 3rd position
    public readonly GoExternalWriter Writer;
#pragma warning restore SA1214 // Readonly fields should appear before non-readonly fields

    public GoPlaintextResult(SpanWriter* writer)
    {
        Writer = GoExternalWriter.FromSpanWriter(writer);
    }

    public GoPlaintextResult(GCHandle streamHandle)
    {
        Writer = GoExternalWriter.FromStreamHandle(streamHandle);
    }
}
