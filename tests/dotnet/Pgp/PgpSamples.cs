namespace Proton.Cryptography.Tests.Pgp;

internal static class PgpSamples
{
    public static readonly byte[] ArmoredLockedPrivateKey =
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
        """u8.ToArray();

    public static readonly byte[] ArmoredLockedPrivateKeyV6 =
        """
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        xYIGaPEh9BsAAAAgj9JlnRNDbtqEXY2twISClTBJxo7ZTuhYpnhiZB8+BcP9JgcC
        FASciERRcaztPm1bsYRGAgQbAwQQ5Ndp1lyX/VA9pUDA23FnewAXIripaa26Na+P
        DT6Ge6tN2JWuGjlW7eHv/Nt/04o5/TrsVQPxbJBoUCo/NYgpwrAGHxsKAAAAQQWC
        aPEh9AMLCQcDFQoIAxYAAgKbAwIeCSKhBtflCBDrT0r/UAY0vU3jG6uMGZUtpxi9
        cGw4/y9UuKJ4BScJAgcCAAAAAN87IMbx2L2Sxl5la/xBL+i9JzeJMGBe6MzLN6hq
        sf6+MFVIhR1GwW7x6VctqXVUFV4HiUHF7JKRBDN2HQcBFNpj3a8Lh4sj+1YXhWxW
        1SOu3wJn3nMw5tMv+6e84TVnLNPhCM0JZHJpdmUga2V5wpsGExsKAAAALAWCaPEh
        9AIZASKhBtflCBDrT0r/UAY0vU3jG6uMGZUtpxi9cGw4/y9UuKJ4AAAAAL5rIOIk
        zZAoKnSKTP8UY0/bUIxGOkGVadLO5nSEZCqeLb1ufnom+D+LsC+F7lCm1EqSPZio
        J33UWiVwhPSVUM5wEkAEXOXzgtRS7PmX30aJo2aFH2C9slNJnXKWDDpNLU/GCseC
        BmjxIfQZAAAAIAp6FpcGSCITQcA11UkYJcTyTgrJ1S1TV68CLyftZ4wG/SYHAhQE
        nIhEUXGs7T5tW7GERgIEGwMEEFoUR6S+5jUIUnvIJf5d8BqoZK5RafHbLtw7rBlU
        yjCRIJUfAEGsN1XXI4HcnFQDm10v6YVRVYl83pgG9kokZcKbBhgbCgAAACwFgmjx
        IfQCmwwioQbX5QgQ609K/1AGNL1N4xurjBmVLacYvXBsOP8vVLiieAAAAAAIliBA
        TtsEPv6uncQSWHUpVIltgZ+jKieCah4ApExDyoYfup36qZVq/t66r//TF51sSYWx
        QM/NoVWBQR4zSYOfq+HngwbFRiweCRdW+Q7P6+f2++HyO9stE2Lduok1zPRrzg8=
        -----END PGP PRIVATE KEY BLOCK-----
        """u8.ToArray();

    public static readonly byte[] ArmoredPublicKey =
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
        """u8.ToArray();

    public static readonly byte[] ArmoredPublicKeyV6 =
        """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        xioGaPEh9BsAAAAgj9JlnRNDbtqEXY2twISClTBJxo7ZTuhYpnhiZB8+BcPCsAYf
        GwoAAABBBYJo8SH0AwsJBwMVCggDFgACApsDAh4JIqEG1+UIEOtPSv9QBjS9TeMb
        q4wZlS2nGL1wbDj/L1S4ongFJwkCBwIAAAAA3zsgxvHYvZLGXmVr/EEv6L0nN4kw
        YF7ozMs3qGqx/r4wVUiFHUbBbvHpVy2pdVQVXgeJQcXskpEEM3YdBwEU2mPdrwuH
        iyP7VheFbFbVI67fAmfeczDm0y/7p7zhNWcs0+EIzQlkcml2ZSBrZXnCmwYTGwoA
        AAAsBYJo8SH0AhkBIqEG1+UIEOtPSv9QBjS9TeMbq4wZlS2nGL1wbDj/L1S4ongA
        AAAAvmsg4iTNkCgqdIpM/xRjT9tQjEY6QZVp0s7mdIRkKp4tvW5+eib4P4uwL4Xu
        UKbUSpI9mKgnfdRaJXCE9JVQznASQARc5fOC1FLs+ZffRomjZoUfYL2yU0mdcpYM
        Ok0tT8YKzioGaPEh9BkAAAAgCnoWlwZIIhNBwDXVSRglxPJOCsnVLVNXrwIvJ+1n
        jAbCmwYYGwoAAAAsBYJo8SH0ApsMIqEG1+UIEOtPSv9QBjS9TeMbq4wZlS2nGL1w
        bDj/L1S4ongAAAAACJYgQE7bBD7+rp3EElh1KVSJbYGfoyongmoeAKRMQ8qGH7qd
        +qmVav7euq//0xedbEmFsUDPzaFVgUEeM0mDn6vh54MGxUYsHgkXVvkOz+vn9vvh
        8jvbLRNi3bqJNcz0a84P
        -----END PGP PUBLIC KEY BLOCK-----
        """u8.ToArray();

    public static readonly byte[] ArmoredSignedMessage =
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
        """u8.ToArray();

    public static readonly byte[] KeyBasedArmoredUnsignedMessage =
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
        """u8.ToArray();

    public static readonly byte[] KeyBasedArmoredUnsignedAeadMessage =
        """
        -----BEGIN PGP MESSAGE-----

        wW0GIQbNb35HeSGiAre0tV/GbIJ0RBH987TnwoaMdi3gNaAmORkx0kHNrD1gZFGR
        9NlcZzK5Pbf3zoufV4hi4UmnUTXUKyiwgZN+HdGHUw64Y4EfBXBI9UT1XhTpOxWv
        2+Hy3o+GdsbMoXmUnyV00lYCCQIMm5Q0gCcycqvZsP8LGVmVtX56seKN7udAbGZY
        odkSSFS90G603l3ka5JE9uIew/44k/mMVDgK6X0wpvLQ9/N0Uqa/dKToC6AX+4N3
        W573Un1hNw==
        -----END PGP MESSAGE-----
        """u8.ToArray();

    public static readonly byte[] KeyBasedArmoredMessageWithNonMatchingSignature =
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
        """u8.ToArray();

    public static readonly byte[] KeyBasedArmoredMessageWithInvalidSignature =
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
        """u8.ToArray();

    public static readonly byte[] PasswordBasedArmoredUnsignedMessage =
        """
        -----BEGIN PGP MESSAGE-----
        Version: GopenPGP 2.2.2
        Comment: https://gopenpgp.org

        wy4ECQMIfTRPnC5dDqLgxdqCI4C5+/m+gjP5ORvD5AHTT2+Y0cLQbfaiZO1hTrB6
        0jsBcUUCH56DIo9QaNEX+u+QZ7FXnbNl5cxPPZ6mNZaUlbudq5TAAPUokV3AADzW
        colcDQE7aAcZl4fvLQ==
        =Cc05
        -----END PGP MESSAGE-----
        """u8.ToArray();

    public static readonly byte[] ArmoredSignedCleartextMessage =
        """
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256

        plain text
        -----BEGIN PGP SIGNATURE-----

        wqsEARYIAF0FgmoSFvIJEOE/bnKDTkKRNRQAAAAAABwAEHNhbHRAbm90YXRpb25z
        Lm9wZW5wZ3Bqcy5vcmcdXoUPq2AnTyU2L3WKkWN2FiEEL8kg4K5LYNzoAqRu4T9u
        coNOQpEAAEMCAQDmECewFjAIs6GOD+V8Id/O0VepTbWDGTY7Udbhz1qCuAEA5/ga
        69pyCEi2ckuXsug6I6xrAR5kqnxQDPJuDozXfgY=
        =wL0x
        -----END PGP SIGNATURE-----
        """u8.ToArray();

    public static readonly byte[] Signature = Convert.FromBase64String(
        "wnUEABYKACcFAmBGWJkJEOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEAACwDAP4ut6l46bH8j8w1odrkNVHGj7VXtzyS+HLb0am6Yihq9AD+K8TqreY0kdrmU0WKS4Codk2FnOBAr2Fp8mU17GKQjwo=");

    public static readonly byte[] ArmoredSignature =
        """
        -----BEGIN PGP SIGNATURE-----
        Comment: https://gopenpgp.org
        Version: GopenPGP 2.1.3

        wnUEABYKACcFAmBGWJkJEOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEA
        ACwDAP4ut6l46bH8j8w1odrkNVHGj7VXtzyS+HLb0am6Yihq9AD+K8TqreY0kdrm
        U0WKS4Codk2FnOBAr2Fp8mU17GKQjwo=
        =nRHS
        -----END PGP SIGNATURE-----
        """u8.ToArray();

    public static readonly byte[] InvalidSignature = Convert.FromBase64String(
        "wnUEABYKACcFAmKV34cJkOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEAAGf8AP0TdxfvBWHPfLX1SQ0ZEls54jtXTxqxiWpZJb8uTJlgRQEAjGkdbpFWkxtrpQDA+UDlb6VptZv7KEcJdeUMRMrhfAs=");

    public static readonly byte[] ArmoredInvalidSignature =
        """
        -----BEGIN PGP SIGNATURE-----
        Version: GopenPGP 2.4.7
        Comment: https://gopenpgp.org

        wnUEABYKACcFAmKV34cJkOE/bnKDTkKRFiEEL8kg4K5LYNzoAqRu4T9ucoNOQpEA
        AGf8AP0TdxfvBWHPfLX1SQ0ZEls54jtXTxqxiWpZJb8uTJlgRQEAjGkdbpFWkxtr
        pQDA+UDlb6VptZv7KEcJdeUMRMrhfAs=
        =br1C
        -----END PGP SIGNATURE-----
        """u8.ToArray();

    public static readonly byte[] ArmoredEncryptedSignature =
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
        """u8.ToArray();

    public static readonly byte[] LongDataPacket = Convert.FromBase64String(
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
        """);

    public static readonly byte[] KeyPacket = Convert.FromBase64String(
        "wV4DQBQ9k/1PHwwSAQdAE3UTz3w3FEZ3Hta9V7a5ZuOk31K4aJNcN/mQ95g84jswwpd3vQphTgzyRatGz6fIxUfO78gCNbXjPMf6vz/TgLXhmrWelq3riy9u+c5Fltvh");

    // From PgpSamples.SessionKeyToken, encrypted with PgpSample.PublicKeyV6
    public static readonly byte[] KeyPacketV6 = Convert.FromBase64String(
        "wW0GIQbNb35HeSGiAre0tV/GbIJ0RBH987TnwoaMdi3gNaAmORn/ESULWgQ39JOymZj+V0ARqBJKGuqLuEPlimvXnX8bYCg0rMjyNZoHZqxyqe3pL+YB6dKYUGAqt1GhhWQjM3A8OhBl8hB4LWA5");

    public static readonly byte[] DataPacket = Convert.FromBase64String("0jsBXraUQc4tquMvg+UUBdgPwCUsf4pASSMeo3T5ofcq7qch4grucRVK1R+LoR2OMtLT9KHKutuCa+l1rQ==");

    public static readonly byte[] SessionKeyToken = Convert.FromBase64String("E4sPzqVRQkoPVe/30kYuE9CRjMqg3nTK5Izt6hTfDWI=");
    public static readonly SymmetricCipher SessionKeyCipher = SymmetricCipher.Aes256;

    public static readonly PgpPrivateKey UnlockedPrivateKey = PgpPrivateKey.ImportAndUnlock(ArmoredLockedPrivateKey, Passphrase, PgpEncoding.AsciiArmor);
    public static readonly PgpPrivateKey UnlockedPrivateKeyV6 = PgpPrivateKey.ImportAndUnlock(ArmoredLockedPrivateKeyV6, Passphrase, PgpEncoding.AsciiArmor);

    public static readonly PgpPublicKey PublicKey = PgpPublicKey.Import(ArmoredPublicKey, PgpEncoding.AsciiArmor);
    public static readonly PgpPublicKey PublicKeyV6 = PgpPublicKey.Import(ArmoredPublicKeyV6, PgpEncoding.AsciiArmor);
    public static readonly PgpSessionKey SessionKey = PgpSessionKey.Import(SessionKeyToken, SessionKeyCipher);
    public static readonly PgpSessionKey SessionKeyV6 = PgpSessionKey.ImportForAead(SessionKeyToken, SessionKeyCipher);

    public static readonly byte[] PlainText = "plain text"u8.ToArray();

    public static readonly byte[] LongPlainText =
        "plain text - Amet vero gubergren diam magna velit sea invidunt sit accusam eirmod dolor labore et aliquyam duo lorem lorem at veniam nonumy iriure eos clita tempor minim et lorem tempor elit ut duo in sadipscing aliquip ut sit lorem et sanctus duo iriure tempor vero volutpat at nam ut velit ut justo ipsum sed dolor amet duis sit dolore lorem dolores consetetur eirmod ex duis eum justo clita ut sit accumsan blandit facilisis nulla molestie sed minim takimata dolores voluptua clita no amet dolores dolore facilisis gubergren sed tempor at sit aliquip ipsum dolor liber stet sit sit sed quis praesent stet aliquyam labore vero et minim diam labore veniam at takimata et voluptua tincidunt elitr lorem accusam duo dolore est elitr at ut ea est ea tincidunt accusam et et et ut laoreet sadipscing dolore sed kasd sed amet invidunt et velit id amet sadipscing tempor wisi sadipscing rebum eu et dolore tempor est at velit quis soluta lobortis est tempor aliquam diam dolore elitr gubergren sadipscing stet eu rebum lorem magna vero feugiat dolores lorem congue labore ullamcorper sit duo magna euismod sadipscing nostrud ut diam magna praesent eum amet tempor sit nonumy ipsum aliquam sadipscing lorem sea ea"u8.ToArray();

    public static ReadOnlySpan<byte> Password => "password"u8;
    public static ReadOnlySpan<byte> Passphrase => "passphrase"u8;
}
