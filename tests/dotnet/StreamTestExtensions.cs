namespace Proton.Cryptography.Tests;

internal static class StreamTestExtensions
{
    extension(MemoryStream stream)
    {
        public ArraySegment<byte> GetSegment()
        {
            return new ArraySegment<byte>(stream.GetBuffer(), 0, (int)stream.Length);
        }

        internal ReadOnlySpan<byte> GetSpan()
        {
            return stream.GetBuffer().AsSpan(0, (int)stream.Length);
        }
    }

    extension(Stream source)
    {
        internal void ReadAll(MemoryStream destination, int readBufferSize = 4096)
        {
            var buffer = new byte[readBufferSize];
            int read;
            while ((read = source.Read(buffer)) > 0)
            {
                destination.Write(buffer.AsSpan(0, read));
            }
        }

        internal async Task ReadAllAsync(MemoryStream destination, int readBufferSize = 4096)
        {
            var buffer = new byte[readBufferSize];
            int bytesRead;
            do
            {
                bytesRead = await source.ReadAsync(buffer.AsMemory(0, readBufferSize), TestContext.Current.CancellationToken).ConfigureAwait(false);
                destination.Write(buffer.AsSpan(0, bytesRead));
            } while (bytesRead > 0);
        }
    }
}
