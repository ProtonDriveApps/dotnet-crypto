using System.Reflection;
using System.Runtime.InteropServices;
using Proton.Cryptography.Tests;

[assembly: AssemblyFixture(typeof(NativeLibraryResolutionFixture))]

namespace Proton.Cryptography.Tests;

public class NativeLibraryResolutionFixture
{
    private const string LibraryName = "proton_crypto";
    private const string LibraryFolderPathFormat = "runtimes/{0}/native";

    public NativeLibraryResolutionFixture()
    {
        NativeLibrary.SetDllImportResolver(typeof(PgpEncrypter).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
        {
            return NativeLibrary.Load(libraryName, assembly, searchPath);
        }

        string os;
        string libraryFileName;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            os = "win";
            libraryFileName = $"{LibraryName}.dll";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            os = "osx";
            libraryFileName = $"{LibraryName}.dylib";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            os = "linux";
            libraryFileName = $"lib{LibraryName}.so";
        }
        else
        {
            throw new InvalidOperationException("Unsupported platform");
        }

        var architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        var rid = $"{os}-{architecture}";
        var libraryPath = Path.Combine(string.Format(LibraryFolderPathFormat, rid), libraryFileName);

        return NativeLibrary.Load(libraryPath);
    }
}
