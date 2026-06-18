using System.Runtime.CompilerServices;
using Proton.Cryptography.Interop;
using Proton.Cryptography.Pgp.Interop;

namespace Proton.Cryptography.Pgp;

/// <summary>
/// Represents an OpenPGP key that can be used for encryption and verification operations.
/// </summary>
public readonly partial struct PgpKey : IVerificationKeyRingSource, IEncryptionKeyRingSource, IDisposable
{
    internal PgpKey(nint foreignHandle)
    {
        ForeignHandle = new ForeignKeySafeHandle(foreignHandle);
    }

    PgpKeyRing IVerificationKeyRingSource.VerificationKeyRing => this;
    PgpKeyRing IEncryptionKeyRingSource.EncryptionKeyRing => this;

    internal ForeignKeySafeHandle ForeignHandle => field ?? throw new InvalidOperationException("Invalid handle");

    public void Export(Stream stream, PgpEncoding encoding)
    {
        var streamHandle = GCHandle.Alloc(stream);

        try
        {
            var outputWriter = InteropWriter.FromStreamHandle(streamHandle);

            using var error = ForeignFunctions.Export(ForeignHandle, forcePublic: false, encoding == PgpEncoding.AsciiArmor, outputWriter);
            error.ThrowPgpExceptionIfAny();
        }
        finally
        {
            streamHandle.Free();
        }
    }

    public unsafe int Export(Span<byte> outputBuffer, PgpEncoding encoding)
    {
        fixed (byte* outputBufferPointer = outputBuffer)
        {
            var spanWriter = new SpanWriter(outputBufferPointer, outputBuffer.Length);

            var outputWriter = InteropWriter.FromSpanWriter(&spanWriter);

            using var error = ForeignFunctions.Export(ForeignHandle, forcePublic: false, encoding == PgpEncoding.AsciiArmor, outputWriter);

            error.ThrowPgpExceptionIfAny();

            return spanWriter.NumberOfBytesWritten;
        }
    }

    public override string ToString()
    {
        using var stream = new MemoryStream();

        Export(stream, PgpEncoding.AsciiArmor);

        stream.Seek(0, SeekOrigin.Begin);

        using var reader = new StreamReader(stream, Encoding.ASCII);

        return reader.ReadToEnd();
    }

    public void Dispose()
    {
        ForeignHandle.Dispose();
    }

    private static partial class ForeignFunctions
    {
        [LibraryImport(Constants.ForeignLibraryName, EntryPoint = "pgp_key_export")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial InteropError Export(
            ForeignKeySafeHandle keyHandle,
            [MarshalAs(UnmanagedType.U1)] bool forcePublic,
            [MarshalAs(UnmanagedType.U1)] bool armored,
            InteropWriter outputWriter);
    }
}
