using SignUniversal.Cli;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Covers how command-line file arguments become concrete paths.
/// </summary>
/// <remarks>
/// These exist because a pipeline migrating from <c>dotnet sign</c> passes
/// <c>**/*.nupkg</c> with a base directory, and the first version of this tool answered
/// "File not found" - which is the sort of thing only a real migration surfaces.
/// </remarks>
public class FileArgumentsTests
{
    [Test]
    public async Task RecursiveGlob_FindsFilesAtEveryDepth()
    {
        using TemporaryTree tree = new();
        tree.WriteFile("top.nupkg");
        tree.WriteFile("a/middle.nupkg");
        tree.WriteFile("a/b/deep.nupkg");
        tree.WriteFile("a/b/ignored.txt");

        bool resolved = FileArguments.TryResolve(["**/*.nupkg"], tree.Root, out List<string> files, out string? error);

        await Assert.That(resolved).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(files.Select(f => Path.GetFileName(f)!))
            .IsEquivalentTo(["top.nupkg", "middle.nupkg", "deep.nupkg"]);
    }

    [Test]
    public async Task BaseDirectory_RootsRelativePatterns()
    {
        using TemporaryTree tree = new();
        tree.WriteFile("dist/one.nupkg");
        tree.WriteFile("dist/two.nupkg");

        bool resolved = FileArguments.TryResolve(["dist/*.nupkg"], tree.Root, out List<string> files, out string? error);

        await Assert.That(resolved).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(files.Count).IsEqualTo(2);
    }

    [Test]
    public async Task LiteralPath_StillWorks()
    {
        using TemporaryTree tree = new();
        string path = tree.WriteFile("app.exe");

        bool resolved = FileArguments.TryResolve([path], baseDirectory: null, out List<string> files, out string? error);

        await Assert.That(resolved).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(files).IsEquivalentTo([Path.GetFullPath(path)]);
    }

    [Test]
    public async Task OverlappingPatterns_YieldEachFileOnce()
    {
        // Signing the same file twice would strip the signature just written.
        using TemporaryTree tree = new();
        tree.WriteFile("a/one.nupkg");

        bool resolved = FileArguments.TryResolve(
            ["**/*.nupkg", "a/*.nupkg"], tree.Root, out List<string> files, out string? error);

        await Assert.That(resolved).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(files.Count).IsEqualTo(1);
    }

    [Test]
    public async Task PatternMatchingNothing_IsAnError()
    {
        // Silence here would mean a release job reporting success having signed nothing.
        using TemporaryTree tree = new();
        tree.WriteFile("a/one.txt");

        bool resolved = FileArguments.TryResolve(["**/*.nupkg"], tree.Root, out List<string> files, out string? error);

        await Assert.That(resolved).IsFalse();
        await Assert.That(files).IsEmpty();
        await Assert.That(error).Contains("**/*.nupkg");
    }

    [Test]
    public async Task MissingLiteralFile_IsAnError()
    {
        using TemporaryTree tree = new();

        bool resolved = FileArguments.TryResolve(["absent.nupkg"], tree.Root, out _, out string? error);

        await Assert.That(resolved).IsFalse();
        await Assert.That(error).Contains("absent.nupkg");
    }

    [Test]
    public async Task MissingBaseDirectory_IsAnError()
    {
        string absent = Path.Combine(Path.GetTempPath(), "signuniversal-absent-" + Guid.NewGuid().ToString("N"));

        bool resolved = FileArguments.TryResolve(["*.nupkg"], absent, out _, out string? error);

        await Assert.That(resolved).IsFalse();
        await Assert.That(error).Contains("Base directory not found");
    }

    [Test]
    public async Task Results_AreOrdered()
    {
        // A reproducible run signs the same inputs in the same sequence.
        using TemporaryTree tree = new();
        tree.WriteFile("c.nupkg");
        tree.WriteFile("a.nupkg");
        tree.WriteFile("b.nupkg");

        bool resolved = FileArguments.TryResolve(["*.nupkg"], tree.Root, out List<string> files, out _);

        await Assert.That(resolved).IsTrue();
        // SequenceEqual, not IsEquivalentTo: order is the whole point of the assertion.
        await Assert.That(files.SequenceEqual(files.OrderBy(f => f, StringComparer.Ordinal))).IsTrue();
        await Assert.That(files.Select(f => Path.GetFileName(f)!))
            .IsEquivalentTo(["a.nupkg", "b.nupkg", "c.nupkg"]);
    }

    private sealed class TemporaryTree : IDisposable
    {
        public TemporaryTree()
        {
            Root = Path.Combine(Path.GetTempPath(), "signuniversal-glob-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteFile(string relativePath)
        {
            string full = Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, "test");
            return full;
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
                // A leaked temp directory is not worth failing a test run over.
            }
        }
    }
}
