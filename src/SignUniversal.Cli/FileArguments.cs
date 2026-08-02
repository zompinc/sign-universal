using Microsoft.Extensions.FileSystemGlobbing;

namespace SignUniversal.Cli;

/// <summary>
/// Turns the file arguments of a command into concrete paths, expanding globs.
/// </summary>
/// <remarks>
/// <para>
/// A shell expands globs before the process sees them, but not always: a quoted pattern
/// arrives verbatim, PowerShell does not expand at all, and <c>**</c> needs
/// <c>globstar</c> even in bash. Pipelines migrating from <c>dotnet sign</c> pass patterns
/// like <c>**/*.nupkg</c> together with a base directory, so both have to work here.
/// </para>
/// <para>
/// This lives in its own class rather than inline in the entry point because argument
/// resolution is logic, and logic in <c>Main</c> is logic no test reaches.
/// </para>
/// </remarks>
internal static class FileArguments
{
    private static readonly char[] WildcardCharacters = ['*', '?'];

    /// <summary>Resolves patterns to files, relative to <paramref name="baseDirectory"/>.</summary>
    /// <param name="patterns">Literal paths or glob patterns, as given on the command line.</param>
    /// <param name="baseDirectory">Where relative patterns are rooted; the current directory when null.</param>
    /// <param name="files">The matched files, deduplicated and ordered.</param>
    /// <param name="error">Why resolution failed, when it did.</param>
    /// <returns><see langword="true"/> if every pattern matched at least one file.</returns>
    public static bool TryResolve(
        IReadOnlyList<string> patterns,
        string? baseDirectory,
        out List<string> files,
        out string? error)
    {
        files = [];
        error = null;

        string root = string.IsNullOrEmpty(baseDirectory)
            ? Directory.GetCurrentDirectory()
            : Path.GetFullPath(baseDirectory);

        if (!string.IsNullOrEmpty(baseDirectory) && !Directory.Exists(root))
        {
            error = $"Base directory not found: {baseDirectory}";
            return false;
        }

        // A set keeps overlapping patterns from signing the same file twice, which would
        // strip the signature just written and replace it with another.
        HashSet<string> matched = new(StringComparer.Ordinal);

        foreach (string pattern in patterns)
        {
            if (pattern.IndexOfAny(WildcardCharacters) < 0)
            {
                string literal = Path.IsPathRooted(pattern) ? pattern : Path.Combine(root, pattern);
                if (!File.Exists(literal))
                {
                    error = $"File not found: {pattern}";
                    return false;
                }

                matched.Add(Path.GetFullPath(literal));
                continue;
            }

            (string searchRoot, string relativePattern) = SplitOnFirstWildcard(pattern, root);

            if (!Directory.Exists(searchRoot))
            {
                error = $"No files matched: {pattern}";
                return false;
            }

            Matcher matcher = new(StringComparison.OrdinalIgnoreCase);
            matcher.AddInclude(relativePattern);

            List<string> hits = matcher
                .GetResultsInFullPath(searchRoot)
                .Select(Path.GetFullPath)
                .ToList();

            if (hits.Count == 0)
            {
                error = $"No files matched: {pattern}";
                return false;
            }

            foreach (string hit in hits)
            {
                matched.Add(hit);
            }
        }

        // Ordered so a run is reproducible: the same inputs sign in the same sequence,
        // whatever order the file system happened to enumerate them in.
        files = [.. matched.OrderBy(path => path, StringComparer.Ordinal)];
        return true;
    }

    /// <summary>
    /// Splits a pattern into the deepest directory that contains no wildcard, and the
    /// pattern relative to it. <c>Matcher</c> needs a concrete root to walk from.
    /// </summary>
    private static (string SearchRoot, string RelativePattern) SplitOnFirstWildcard(string pattern, string root)
    {
        string normalized = pattern.Replace('\\', '/');

        if (!Path.IsPathRooted(pattern))
        {
            return (root, normalized);
        }

        string[] segments = normalized.Split('/');
        int firstWildcard = Array.FindIndex(segments, s => s.IndexOfAny(WildcardCharacters) >= 0);
        if (firstWildcard < 0)
        {
            return (root, normalized);
        }

        string searchRoot = string.Join('/', segments.Take(firstWildcard));
        if (string.IsNullOrEmpty(searchRoot))
        {
            searchRoot = "/";
        }

        return (searchRoot, string.Join('/', segments.Skip(firstWildcard)));
    }
}
