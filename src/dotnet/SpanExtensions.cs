namespace Proton.Cryptography;

internal static class SpanExtensions
{
    extension<TIn, TOut>(Span<TOut> span)
    {
        public void FillWithTransform(IReadOnlyList<TIn> input, Func<TIn, TOut> convertFunction)
        {
            for (var i = 0; i < input.Count; ++i)
            {
                span[i] = convertFunction.Invoke(input[i]);
            }
        }
    }
}
