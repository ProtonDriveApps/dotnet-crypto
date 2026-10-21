namespace Proton.Cryptography.Tests.Srp;

internal static class SrpSamples
{
    private static string DataDir => Path.Combine(AppContext.BaseDirectory, "data");

    private static byte[] SrpFile(string name) =>
        File.ReadAllBytes(Path.Combine(DataDir, "srp", name));

    private static byte[] SrpB64File(string name) =>
        Convert.FromBase64String(File.ReadAllText(Path.Combine(DataDir, "srp", name)).Trim());

    private static string SrpTextFile(string name) =>
        File.ReadAllText(Path.Combine(DataDir, "srp", name));

    public const int BitLength = 2048;

    public static readonly string Username = SrpTextFile("username.txt");
    public static readonly string SignedModulus = SrpTextFile("signed_modulus.asc");

    public static readonly byte[] Modulus = SrpB64File("modulus.b64");
    public static readonly byte[] Salt = SrpB64File("salt.b64");
    public static readonly byte[] PasswordHashingSalt = SrpB64File("password_hashing_salt.b64");
    public static readonly byte[] Verifier = SrpB64File("verifier.b64");
    public static readonly byte[] ServerSecret = SrpB64File("server_secret.b64");
    public static readonly byte[] ServerEphemeral = SrpB64File("server_ephemeral.b64");
    public static readonly byte[] ClientProof = SrpB64File("client_proof.b64");
    public static readonly byte[] ClientEphemeral = SrpB64File("client_ephemeral.b64");
    public static readonly byte[] ServerProof = SrpB64File("server_proof.b64");

    public static ReadOnlySpan<byte> Password => SrpFile("password.txt");
    public static ReadOnlySpan<byte> DerivedPassword => SrpFile("derived_password.txt");
}
