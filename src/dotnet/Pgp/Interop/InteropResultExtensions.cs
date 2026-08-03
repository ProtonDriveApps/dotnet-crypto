using System.Runtime.ExceptionServices;
using Proton.Cryptography.Interop;

namespace Proton.Cryptography.Pgp.Interop;

internal static class InteropResultExtensions
{
    extension(InteropError interopError)
    {
        public void ThrowPgpOrStreamExceptionIfAny(params ReadOnlySpan<ExceptionRecordingStream?> streams)
        {
            if (!interopError.TryGetMessage(out var message))
            {
                return;
            }

            foreach (var stream in streams)
            {
                if (stream?.TakeLastException() is { } streamException)
                {
                    ExceptionDispatchInfo.Capture(streamException).Throw();
                }
            }

            throw new PgpException(message);
        }
    }
}
