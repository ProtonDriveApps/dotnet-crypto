namespace Proton.Cryptography.Pgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct InteropPlaintextResult
{
    public bool HasVerificationResult;
    public nint VerificationResultHandle;
#pragma warning disable SA1214 // Readonly fields should appear before non-readonly fields
    // Warning disabled because this field needs to be in 3rd position
    public readonly InteropWriter Writer;
#pragma warning restore SA1214

    public InteropPlaintextResult(SpanWriter* writer)
    {
        Writer = InteropWriter.FromSpanWriter(writer);
    }

    public InteropPlaintextResult(GCHandle streamHandle)
    {
        Writer = InteropWriter.FromStreamHandle(streamHandle);
    }
}
