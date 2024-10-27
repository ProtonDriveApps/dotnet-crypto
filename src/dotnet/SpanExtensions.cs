namespace Proton.Cryptography;

internal static class SpanExtensions
{
    public static void FillWithTransform<TIn, TOut>(this Span<TOut> span, IReadOnlyList<TIn> input, Func<TIn, TOut> convertFunction)
    {
        for (var i = 0; i < input.Count; ++i)
        {
            span[i] = convertFunction.Invoke(input[i]);
        }
    }
}
