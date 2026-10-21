using Proton.Cryptography.Interop;
namespace Proton.Cryptography.Pgp.Interop;

internal static class InteropResultExtensions
{
    extension(InteropError interopError)
    {
        public bool SucceededOrThrowPgpException()
        {
            interopError.ThrowPgpExceptionIfAny();

            return true;
        }

        public void ThrowPgpExceptionIfAny()
        {
            if (!interopError.TryGetMessage(out var message))
            {
                return;
            }

            throw new PgpException(message);
        }

        public void ThrowPgpOrStreamExceptionIfAny(params ReadOnlySpan<ExceptionRecordingStream?> streams)
        {
            if (!interopError.TryGetMessage(out var message))
            {
                return;
            }

            ExceptionRecordingStream.ThrowIfAnyException(streams);

            throw new PgpException(message);
        }
    }
}
