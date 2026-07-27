namespace SignUniversal.Core.Tests;

/// <summary>A scratch directory that deletes itself.</summary>
internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"sign-universal-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    /// <summary>Gets the directory path.</summary>
    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // A leftover scratch directory is not worth failing a test over.
        }
    }
}
