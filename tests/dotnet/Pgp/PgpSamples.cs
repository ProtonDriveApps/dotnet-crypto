namespace Proton.Cryptography.Tests.Pgp;

internal static class PgpSamples
{
    public const string ArmoredLockedPrivateKey =
        """
        -----BEGIN PGP PRIVATE KEY BLOCK-----
        Version: GopenPGP 2.1.3
        Comment: https://gopenpgp.org

        xYYEYEZQKRYJKwYBBAHaRw8BAQdAeu8Lmx4mNZtO0aQ93fMOjT3boFI89sVFPVTS
        zrjwzff+CQMIABamt2xm1zdglBUUu5oOsIAnMkANVwz3ZShdUbeoCaRrgInIBNnP
        YFn9rRVgYMg/t/h+RGUxm4oAzMUhiX4DKyukYUbqQN1IUuVPybXwec0XdGVzdCA8
        dGVzdEBleGFtcGxlLmNvbT7CiAQTFggAOgUCYEZQKQkQ4T9ucoNOQpEWIQQvySDg
        rktg3OgCpG7hP25yg05CkQIbAwIeAQIZAQMLCQcCFQgCIgEAAG+sAPwJ6nw5kwwe
        AZI8yS2LkKrI7ft1R5oLVWrW6QC8diwOPwEAtvTw9vrN80yhFnMZo6WP+oLIUMD1
        3nMyzsk4qzuuagnHiwRgRlApEgorBgEEAZdVAQUBAQdAplz6h26HDDaapjlnG+qF
        jXuPQQIzoX1zNgY+77o2syADAQoJ/gkDCL1bO0y05YqHYHariMxGcMFnLJBzizD/
        t5s8oCq5xt5l8dj+lubUbnuGzqocthmtMFtW6ftzG8myKu9clyxQAWoUB31YzZiv
        fqgK/yEIKo7CeAQYFggAKgUCYEZQKQkQ4T9ucoNOQpEWIQQvySDgrktg3OgCpG7h
        P25yg05CkQIbDAAAt2QA/RPN+hukCYHrK1sUN+g4G1DXnFkUtXrazRtDd0a57xxa
        AP4zK8gpETp13qCV6dooRD4LP2g/IAB+/f+VitR3JYptAw==
        =oSE9
        -----END PGP PRIVATE KEY BLOCK-----
        """;

    public const string ArmoredPublicKey =
        """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: GopenPGP 2.1.3
        Comment: https://gopenpgp.org

        xjMEYEZQKRYJKwYBBAHaRw8BAQdAeu8Lmx4mNZtO0aQ93fMOjT3boFI89sVFPVTS
        zrjwzffNF3Rlc3QgPHRlc3RAZXhhbXBsZS5jb20+wogEExYIADoFAmBGUCkJEOE/
        bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpECGwMCHgECGQEDCwkHAhUIAiIB
        AABvrAD8Cep8OZMMHgGSPMkti5CqyO37dUeaC1Vq1ukAvHYsDj8BALb08Pb6zfNM
        oRZzGaOlj/qCyFDA9d5zMs7JOKs7rmoJzjgEYEZQKRIKKwYBBAGXVQEFAQEHQKZc
        +oduhww2mqY5ZxvqhY17j0ECM6F9czYGPu+6NrMgAwEKCcJ4BBgWCAAqBQJgRlAp
        CRDhP25yg05CkRYhBC/JIOCuS2Dc6AKkbuE/bnKDTkKRAhsMAAC3ZAD9E836G6QJ
        gesrWxQ36DgbUNecWRS1etrNG0N3RrnvHFoA/jMryCkROnXeoJXp2ihEPgs/aD8g
        AH79/5WK1Hclim0D
        =HWbV
        -----END PGP PUBLIC KEY BLOCK-----
        """;

    public const string ArmoredSignedMessage =
        """
        -----BEGIN PGP MESSAGE-----
        Comment: https://gopenpgp.org
        Version: GopenPGP 2.1.3

        wV4DQBQ9k/1PHwwSAQdAEFrdth7fk+jBQL73FEMMQtKL8+Wx9vA3AYByHbWWzhAw
        Hm4mCkIgD/aN95gmnXYAuWF0W9YI269sT+rwF0ZMsG70O+YtxdspZ2mTd0qU8EuY
        0sABAUSM7Jc2w5M7mImcQwk4nsjDGbBXsz9ahHv8rhKHZvdAzZ2pHkfs1hV4cT4Z
        EjUfcbUyIrqtIQwc5er3QZta1+ATCrVfeXyTElD/+b4FmyxIxEWXwZB0ZHutYMhy
        EBfO4v8A/NPt1KbRqvoWR4J3Sc2s5WRzIQ73b9nwXBjUfq6aQVTYbbmTFVehqoUn
        Gh+PevejcufLD97+z1Lr0aDt7TJKu9aDgXtdwlLwqzAjIa/GujGy2s1/cQttzIts
        tP75Rg==
        =Qfb4
        -----END PGP MESSAGE-----
        """;

    public const string KeyBasedArmoredUnsignedMessage =
        """
        -----BEGIN PGP MESSAGE-----
        Version: GopenPGP 2.1.3
        Comment: https://gopenpgp.org

        wV4DQBQ9k/1PHwwSAQdAdQ6dYeVO4cgO+7Ea7cW8JsHdpYpg5/zaMmGsjmWCWkow
        521lHB2w+cOooiUV2BgaphRlQUJA785g8eMeRzorI3fVsZW3cf+KiV7dtim+baEK
        0jsBbWP3h5vTcIoYylnxpwNugpuZz8/ocvGzrBxuS4avxpeyMORou4x2qCiKcGrR
        7DrUSz9LxMH3CSd1Xg==
        =44WS
        -----END PGP MESSAGE-----
        """;

    public const string KeyBasedArmoredMessageWithNonMatchingSignature =
        """
        -----BEGIN PGP MESSAGE-----
        Version: GopenPGP 2.4.7
        Comment: https://gopenpgp.org

        wV4DQBQ9k/1PHwwSAQdAX3H5fj7c7Z7SS7eNY33/JYqxvO0Y7GUl9NvGcHzyDmUw
        hCgTpAHEz90AnALkv9lIGGJB0tOYDOyQkovAisz0bPny4XqvIvOz3uW0rNrZFvpd
        0sABAZOTpmVYjmv8l7Rfmc6ZzD/SjZnFroxn9QEFr/Ge2yQp1lO7qj15/zKjVwIz
        frDFKQzJ1TAhS55hMpvotQnS9HrnRZL59FxRxTQyvoNFktrDdO7cdOqjqGbYVyFx
        aa5S4D5uQmMgGTEZlCE1b17fhMKWWVIdJdiUA9vhTzpMaCMSHKjwinNc/jkTGfk6
        /NvDVXUPU7IsXxrbtMvkXxoea75DYNE68aN0dztxHDSDmtoGIsz+BEhq+K87KmxU
        L0tq9w==
        =HeF7
        -----END PGP MESSAGE-----
        """;

    public const string KeyBasedArmoredMessageWithInvalidSignature =
        """
        -----BEGIN PGP MESSAGE-----
        Version: GopenPGP 2.4.7
        Comment: https://gopenpgp.org

        wV4DQBQ9k/1PHwwSAQdAGrDQW6DJVzS3xd3qhZzUrJUKBWkurHZezHS43ytUlXow
        fuWQnNeRPbYG1/BN+eYPxUn2we1VRCE2trqEH8mcFdfE7uGmYMCPVwNjxQE9Ew5Q
        0sABAX4Gk3lFVQU/kvzea/rEbC8HWmlQAxm61jiBd/VbnnBxTTK7KNHeHJ13RGKA
        spHv6Wcr5LRUrxGDl0Dzul8BdeO4SOAcSHVVz2W3h7v/a2PvbYiTqMFNAg9Xv8L9
        1CjqWMTIfHCYOr+JG0sW6zeRXEe6+Ln7QdVqdGDLda8LfAXkfzw4K7g+sWtTGjdE
        dRCTELUUinGT3jnpCNoeRne52UbSkLfzRMWF/8xN3/J192sOianP6axGNdZaMXHZ
        Bo5oMw==
        =J0RW
        -----END PGP MESSAGE-----
        """;

    public const string PasswordBasedArmoredUnsignedMessage =
        """
        -----BEGIN PGP MESSAGE-----
        Version: GopenPGP 2.2.2
        Comment: https://gopenpgp.org

        wy4ECQMIfTRPnC5dDqLgxdqCI4C5+/m+gjP5ORvD5AHTT2+Y0cLQbfaiZO1hTrB6
        0jsBcUUCH56DIo9QaNEX+u+QZ7FXnbNl5cxPPZ6mNZaUlbudq5TAAPUokV3AADzW
        colcDQE7aAcZl4fvLQ==
        =Cc05
        -----END PGP MESSAGE-----
        """;

    public const string Signature =
        "wnUEABYKACcFAmBGWJkJEOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEAACwDAP4ut6l46bH8j8w1odrkNVHGj7VXtzyS+HLb0am6Yihq9AD+K8TqreY0kdrmU0WKS4Codk2FnOBAr2Fp8mU17GKQjwo=";

    public const string ArmoredSignature =
        """
        -----BEGIN PGP SIGNATURE-----
        Comment: https://gopenpgp.org
        Version: GopenPGP 2.1.3

        wnUEABYKACcFAmBGWJkJEOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEA
        ACwDAP4ut6l46bH8j8w1odrkNVHGj7VXtzyS+HLb0am6Yihq9AD+K8TqreY0kdrm
        U0WKS4Codk2FnOBAr2Fp8mU17GKQjwo=
        =nRHS
        -----END PGP SIGNATURE-----
        """;

    public const string InvalidSignature =
        "wnUEABYKACcFAmKV34cJkOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEAAGf8AP0TdxfvBWHPfLX1SQ0ZEls54jtXTxqxiWpZJb8uTJlgRQEAjGkdbpFWkxtrpQDA+UDlb6VptZv7KEcJdeUMRMrhfAs=";

    public const string ArmoredInvalidSignature =
        """
        -----BEGIN PGP SIGNATURE-----
        Version: GopenPGP 2.4.7
        Comment: https://gopenpgp.org

        wnUEABYKACcFAmKV34cJkOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEA
        AGf8AP0TdxfvBWHPfLX1SQ0ZEls54jtXTxqxiWpZJb8uTJlgRQEAjGkdbpFWkxtr
        pQDA+UDlb6VptZv7KEcJdeUMRMrhfAs=
        =br1C
        -----END PGP SIGNATURE-----
        """;

    public const string ArmoredEncryptedSignature =
        """
        -----BEGIN PGP MESSAGE-----
        Comment: https://gopenpgp.org
        Version: GopenPGP 2.1.3

        wV4DQBQ9k/1PHwwSAQdAGwFOg3QWTRi+m4Txi/dfC7/pAM9FxFUlWjILGKargxgw
        0C52rKPUXLEep6b2b/izPkS0FMq87J6rW2hUsYZznuBwI5aYM/98GYfPOv2CLEQo
        0qgB3rLPvQY4nkNxV/9vMeR8zbp8A9Xcbl8dREPHJgvkU6gfqqfjdEXnyM9/+/ko
        dtuN+LOfamwTOxUbVPBuC++VzxSfw1BZ3jlRslypvMagUj9bGDVW3hqgfENQH/Q6
        lolwl2GseYaYGVhfXYdhrzwbOFVumEuiF6aSQTvQpjCdZWQkTMrMMjjDFw3xt2+Z
        4htYxdGBo4fjeDNNeW2QOHdoLWBa1M8c/1M=
        =1v+N
        -----END PGP MESSAGE-----
        """;

    public const string LongDataPacket =
        """
        0uoBCMsEJkKs6wwow3uuUVmWWR/rCZhay3Uq8fMksgusifoi0R6ZlBYoshKU60t9oJkz2t2Rdxfqqho6VO/TDEovZOq49dLFR3AVuHiWD5gES33iR1LrIBJQZgmmiXChmbrIpSS1XX45idj8SQF2FSmE8
        xoWObz2NkpXUt9h6VlfyzpT9ENgG10vgIr8tS0YnsQkgICE/uVR1tZ48H38r9+PMyFAGi0sG9RxsvNIXqMl9iISY162Kg/HG7N4I2ASAL4/S/3S+nZjSsG5D2YTnkmx5uX7JBgHUPYiq0B/is43gzWlks
        D2+xrE2e5wAP1ijRXPDbYsRQkVJMA/2vTs4oDE/MKPULs7Iu2Ysx/4SZTCqGu4n41T0tFQmeSKKpMlb1dTnP93jG2/3AeqDGyUFO9tt0oWMPYFeGRQkKEx6aZIALPIE/89oDBP+jqPA5oDyZv7E8/2m6j
        yHhX5ha6tCmNw+n+ep1Mala0zRr5fiBAFWSlL//CAYubZHhmLSmgoVJqS8o3FvPKtZB5WDGXqcp+3bGAOkeAWKHUfYRkKwp8LLDLN3z6A413KHmPFkRwoQ8tR6k3m/ajoPMUTXtz5ErMkDrG7+m9ZV5Hn
        /ffkl4zc+iyhrs1Jm7UANfiVga/+bIQx1FQLQzZpRskA5h0cwxPhgyaoZhZuG9xus76rOCMbve+YIYDewtkFfHT1iRRqELgR6XkkqWk3OAhfMSbxL9DQ6a9zJF544fkBfCPsZk1O0lPFz2sCsvwabzXo0
        9LEDSS63PunE4mnuEeO0hvJid6eKJI3x76Jkho/HTuoY5EoXN0ZXvBZ0+yhxVn7iBRpIZdmyHkdakWMl7iZJj5An7jPoKfTJh84BB5QzPGNTWUY8ruzVLs7k56I9NdS4bu8Li+YKVos5dPzFp/8lykAAL
        yI8NOuDcj69IZrPm2W2h+Ifp64YdaExqtwiaZxMcZzDwIpb+EtAFkkQIKAvCIgyrsaSNcI6fdyW16UQMVkl0c/WhRDA25SwQSmix6RydNCKyz0cZoQ+YV59IzSuNv7OFQDELWcdxBuIptAbIDAk4dL612
        cHTYq9BjVugy+i82fXipyb77cjo9r9SWzoQNAo8CLAiUSEgI7G2Dkc8Nwpx25L3Q8v6PnEEmc6YnYJrfD14rJ9fotSQ31EnFJYBl5zr+Om/vZfLfPyW9UsAepj6N86XmZjA/ULqR9Btc+oMkDf310fCVr
        xx8R540MuVlrTr4e9aBvyh5h1KtuaF3OW1l0JLeN1prMPm8j03mUCSsAcIYdo/wP998JQEvmxgaBuTf8rS/qTSmSOAKmK0KNkXXVqNYYBTWUKgSPJq95ut5vN296UacDOegC7IK0chFjST8DwClqcsQpV
        S3ZAKyDlbiKh3WYrTQKdUwOUmSZtF4ZX6SpIDBHjULqJZGESOK2JPkaqh8d3wK0sEDFWR7sGvU8VvqD8EJqYq4HonpulUohShX9BkmmPSMTyTUoWwJxq5EUFj95/WLicpCBuMAZS/tDuXIq8Z6YiQoyuI
        Dd5kcrC4QOSvIVhKJxBf+EM+E16oJBkUKm/jYPb22+ASpfXsCPp/4STCIOkdumFJwAG7oxqMV2I+ThT1umLhY01N+9T357qkzacAnOVW7X8RAs8th3Fkr62Tav/GSesQkuu1Cf1Q2sDEhPUliVsz9NnA=
        =
        """;

    public const string PlainText = "plain text";

    public const string LongPlainText =
        "plain text - Amet vero gubergren diam magna velit sea invidunt sit accusam eirmod dolor labore et aliquyam duo lorem lorem at veniam nonumy iriure eos "
        + "clita tempor minim et lorem tempor elit ut duo in sadipscing aliquip ut sit lorem et sanctus duo iriure tempor vero volutpat at nam ut velit ut justo"
        + " ipsum sed dolor amet duis sit dolore lorem dolores consetetur eirmod ex duis eum justo clita ut sit accumsan blandit facilisis nulla molestie sed mi"
        + "nim takimata dolores voluptua clita no amet dolores dolore facilisis gubergren sed tempor at sit aliquip ipsum dolor liber stet sit sit sed quis prae"
        + "sent stet aliquyam labore vero et minim diam labore veniam at takimata et voluptua tincidunt elitr lorem accusam duo dolore est elitr at ut ea est ea"
        + " tincidunt accusam et et et ut laoreet sadipscing dolore sed kasd sed amet invidunt et velit id amet sadipscing tempor wisi sadipscing rebum eu et do"
        + "lore tempor est at velit quis soluta lobortis est tempor aliquam diam dolore elitr gubergren sadipscing stet eu rebum lorem magna vero feugiat dolore"
        + "s lorem congue labore ullamcorper sit duo magna euismod sadipscing nostrud ut diam magna praesent eum amet tempor sit nonumy ipsum aliquam sadipscing"
        + " lorem sea ea";

    public static readonly byte[] KeyPacket = Convert.FromBase64String(
        "wV4DQBQ9k/1PHwwSAQdAE3UTz3w3FEZ3Hta9V7a5ZuOk31K4aJNcN/mQ95g84jswwpd3vQphTgzyRatGz6fIxUfO78gCNbXjPMf6vz/TgLXhmrWelq3riy9u+c5Fltvh");

    public static readonly byte[] DataPacket = Convert.FromBase64String("0jsBXraUQc4tquMvg+UUBdgPwCUsf4pASSMeo3T5ofcq7qch4grucRVK1R+LoR2OMtLT9KHKutuCa+l1rQ==");

    public static readonly byte[] SessionKeyToken = Convert.FromBase64String("E4sPzqVRQkoPVe/30kYuE9CRjMqg3nTK5Izt6hTfDWI=");
    public static readonly SymmetricCipher SessionKeyCipher = SymmetricCipher.Aes256;

    public static readonly PgpPrivateKey PrivateKey = PgpPrivateKey.ImportAndUnlock(
        Encoding.ASCII.GetBytes(ArmoredLockedPrivateKey),
        Passphrase,
        PgpEncoding.AsciiArmor);

    public static readonly PgpPublicKey PublicKey = PgpPublicKey.Import(Encoding.ASCII.GetBytes(ArmoredPublicKey), PgpEncoding.AsciiArmor);
    public static readonly PgpSessionKey SessionKey = PgpSessionKey.Import(SessionKeyToken, SessionKeyCipher);

    public static ReadOnlySpan<byte> Password => "password"u8;
    public static ReadOnlySpan<byte> Passphrase => "passphrase"u8;
}
