namespace Proton.Cryptography.Tests.Srp;

internal static class SrpSamples
{
    public const int BitLength = 2048;

    public const string Username = "Test";

    private const string ModulusBase64 =
        "UwuGCW/iuoTL1FGO4mOGv/NTEnvJVFU3tVFIN0YZOSy5DAXqNfADJYPZko62MJZCI23w0usAc2vYrMNJroCUyX8zCu4PST520cCSyYxhuIDJQsVNm6CuJIOq1qEl5gFoXs3YvZhMTxXt3sjSH4c8XOL0exYGnZUCP2yvLkwlcD3PLgnGbjkn4Z1MY3fVwx+estiB6CC8uXdHJ0w/Rl3zwXv6ycN99rJVIJaXdVrAaFF6GRNkv316OjtDIWBqVAWQ1woaCu6lgLdzG4nS0v1OxdCrZe2RdXBBweCIq8jEusK5tYbbA28DXwS8ntat4HE8/LhbrlVsTT+ioAuc5V0ExA==";

    public const string SignedModulus =
        $"""
         -----BEGIN PGP SIGNED MESSAGE-----
         Hash: SHA256

         {ModulusBase64}
         -----BEGIN PGP SIGNATURE-----
         Version: ProtonMail
         Comment: https://protonmail.com

         wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAAC19gD/e6Zlyhp7vEvHpSxwO3sA
         W9VEifu7lX6cMzHJERu3UHkBAO8alVbq0yo2Gi1utT506E0oLEFsufIn0Qi0
         XdTwqnEL
         =jJ38
         -----END PGP SIGNATURE-----
         """;

    public static readonly byte[] Modulus = Convert.FromBase64String(ModulusBase64);

    public static readonly byte[] Salt = Convert.FromBase64String("46YZLllCYrstog==");

    public static readonly byte[] PasswordHashingSalt = Convert.FromBase64String("JfLvsiBB+sw1BlhfsyNn3g==");

    public static readonly byte[] Verifier = Convert.FromBase64String(
        "PDC/EESbJSNXbhkvdwe7JOwDFrXZyX/S7LE0KLblsm+vwNs49ImDVwaYLsiJaY3+o0cxC8EVUnuGw1ejZao+8Wk7TjqS/8e32+v5u3LFPdrBJHb5/QUuRWjS1RY8IcG4ujq0X4trjgyFbRNuwF8mPOUvEjmGLVvzjBx4JA20HEO+2OsU1T4n7RQP/aDI3EpcvJn8XRKrQ54gdfVbMyKq1FsFmw3/WLEAZ/Kz4V4SMEDp9zQwHw3aLaf8yam2g4hAGbF2kk3n0tq6FaJT0bD59vSlXSe9r3Jt2GP62JNFY/QJbXoIa+JRg1l79wEtj/Jqx8wzsF6ullkJVSzpdV/6dA==");

    public static readonly byte[] ServerSecret = Convert.FromBase64String(
        "2oKfxoBag9j6hfu6ZCWpyWLra96TzbZYPWG0rAA8CSRC8aJ6ga9iO7OarSdHac8LXPxpjv26QhHfymWqlGsVtBNkjCn7UDCHP0F7cqXxzbMyfUc5slXE1Es/VSTd0MbkLfccvTLtRg1R46UMk45FD1SJLYEhC/jswfCgl5Ydn6BxDjZNi/vbI6bWS/XIcpchS2vJNCsPeDKuV5r8ujEvnFeFkpfXo5Yjt2lTqeUrFyzrxoWwnNzCcV/P6UrHWws5/3eu6HOgLmQ90jItQ86aVX6+mRf27jT/qk5aj+/XgoexM6cpi7OSrjTfKB+M2kGUBIZRIda/c2KnKdPM/5T6yw==");

    public static readonly byte[] ServerEphemeral = Convert.FromBase64String(
        "W7PClOzywoIYaaagbKnQFEE9/6sMQp5mr9Hc4QqyFZKvFIdGxX+zr9L/rc7Zc3PjMDKQi4uN5WsWhShWgqJoa7pKjiTcknspgqx8KHFh1PJnapoP5vWb6SQZv7a9x6LuPnV8wLBmgMy0RS+nG/1zMCYaDF6Tf+lzPbN1uxHlCvCCLVb77sluE4/aEdZtqqJRgRkvSLp5LwaA9WS/bt+e2dGUr07YUDiIE/pTFCypaZLE0LOUumTwLzahz8DW+K0VQcvYgSiTbj39DAB+b6pF4I/Xbiqrr3JSnhGqVKCRmtLRc6KrgmHeJzeH1Wl9XpRCSGUaRqCmUJRhxQGBWFX0FA==");

    public static readonly byte[] ClientProof = Convert.FromBase64String(
        "PVWumGWCNVbcmpzBWWZbg5dTdNH+r8/cFhzeAna9O49ANhaRQL4zCWOUmYi7hzX/GVf9xYJpUniXHWPfk11tqqDu+jvwBLvf9bjJjj4PlBwjfr8T8My4uLLZjf6spsuoAxCIehJp/OXcNVV70V4WvDJeqD40ZV5kI1t/pgtYAP2uhmo5BmkM550cqoUjEt2oo1GvH8UVB16eZZeVuNwzNp2QWsvO+bpw7+sBzN4Ham2A/Py3tcfyJchmr1lgB3hnuAPs+Ut4dvWlCPC93Sx6OYBP2p2U1k9Nkm+Ftf4DnJ9X0HNGgn+q1KSCS0Vd+68O2yd7LS2KxF20312VfO9l5w==");

    public static readonly byte[] ClientEphemeral = Convert.FromBase64String(
        "H2Kn9R8i4kJ0B6htnwz/BuojURW6LR98dP2jAgTqLDSXJ09Lif0KvNKhYNsK7IgNEMQyenU5YTpMWgc0HWfqNoTSPfkwzQd9DNOhdw7en5kvumKpH8xmBj53utR3pF6g2gPi6tyVN9yK1tvllGudaBIwSzkoPALHv6oinx1sdScr5Lpw+WCqOvACKM+tmDKJ6gdRbTQhYPQys2+TUyLodIWE1AR6cpX46ZhGW/V3rSAVea7P2jpnt0j9qKamNZDwho/tBuNE5Av2uZNbAJe0Yj3S9sbQ5aQbbYXNgc79LKiBydCMFIpvv5e6zs2+P9OBBmxDFkMu6zoLj513p4h5bw==");

    public static readonly byte[] ServerProof = Convert.FromBase64String(
        "zMauPZ5kp93nRnFRoIy1z+XL1+NDTRFMWpckhnt37yDYMTPZtnltXLAHhHe9JjTZM30izQElGh08gu1pQgG3o+5mWAllTyNRDOFGctFtCybhIAE3C3nXWqG8+ZQmCFsnwqUO70sv/UGB+lVX4Yfhb8dogbTWof4ja6dTUyITA87E5HvXtOHoN21gVyp87DK5aMRzGV+O7Kp6tIkZssiTCYoUh0pvfMwv8snlSCI1P5lF27fjHLbgBDz7Qqb3NK+HleUV5yGvXfB7X6h3lUQjGnGbYiS0aBxpKOXZeCOSVOeyruk655pDB4T2kTfOFDW5wBIMFkWwDP61f9NvhPFmXQ==");

    public static ReadOnlySpan<byte> Password => "Password\n密碼\n👍\r\n"u8;

    public static ReadOnlySpan<byte> DerivedPassword => "$2y$10$HdJtqg//8quz/jfdqwLl1eaa5orjqwAkd28IBfgrlF5ofUaGEel9i"u8;
}
