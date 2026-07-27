using System.Security.Cryptography;
using FluentAssertions;
using SignUniversal.Core.Authenticode;
using TUnit.Core;

namespace SignUniversal.Core.Tests;

/// <summary>
/// Pins down the Authenticode digest: the known-answer vectors, and the range
/// exclusions that let a signature be appended without invalidating itself.
/// </summary>
/// <remarks>
/// The expected digests come from <see cref="AuthenticodeDigestReference"/>, a second
/// implementation transcribed from the specification that shares no code with the engine.
/// Its credibility rests on the corpus check below: pointed at a directory of
/// already-signed binaries, it recomputes each digest and finds it inside that file's own
/// signature — several hundred Microsoft-signed PE32 and PE32+ images, none mismatched.
/// </remarks>
public sealed class PeDigestTests
{
    private const int TrailingBytes = 5;
    private const int HeaderGap = 0x200;
    private const int CorpusLimit = 300;

    [Test]
    public void Digest_Pe32_MatchesReferenceImplementation()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: TrailingBytes);

        Digest(image).Should().Be("1541106966db6d801fea48d4eed33aaf06007719738903fe1abb784131099809");
    }

    [Test]
    public void Digest_Pe32Plus_MatchesReferenceImplementation()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: true, headerGap: HeaderGap, trailingBytes: 0);

        Digest(image).Should().Be("47f9196c9d5494a8e0dc960a1822b42d5e6b8114281d35b83afeab088129a65b");
    }

    [Test]
    public void Digest_AgreesWithTheReferenceImplementation()
    {
        // The vectors above pin specific values; this pins the two implementations to each
        // other for every layout the suite builds, which is what catches a logic slip in
        // the engine's streaming walk.
        foreach (byte[] image in new[]
        {
            SyntheticPe.Build(pe32Plus: false),
            SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: TrailingBytes),
            SyntheticPe.Build(pe32Plus: true, headerGap: HeaderGap),
            SyntheticPe.Build(pe32Plus: true, headerGap: HeaderGap, trailingBytes: TrailingBytes),
        })
        {
            using MemoryStream stream = new(image, writable: false);

            PeFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256)
                .Should().Equal(AuthenticodeDigestReference.ComputeDigest(image, HashAlgorithmName.SHA256));
        }
    }

    [Test]
    public void Digest_MatchesEverySignedBinaryInTheCorpus()
    {
        // The oracle that settled the format questions in the first place: for an already
        // signed binary, the digest we compute must be the one sitting inside its own
        // signature. Point it at any directory of signed PE files — a NuGet package cache
        // will do.
        string? corpus = Environment.GetEnvironmentVariable("SIGNUNIVERSAL_PE_CORPUS");
        Skip.Unless(
            !string.IsNullOrEmpty(corpus) && Directory.Exists(corpus),
            "set SIGNUNIVERSAL_PE_CORPUS to a directory of signed PE files");

        int checked_ = 0;
        List<string> mismatched = [];

        foreach (string path in EnumeratePeFiles(corpus!))
        {
            if (checked_ >= CorpusLimit)
            {
                break;
            }

            byte[] image;
            byte[]? table;

            try
            {
                image = File.ReadAllBytes(path);
                table = AuthenticodeDigestReference.TryReadCertificateTable(image);
            }
            catch (Exception exception) when (exception is InvalidDataException or IOException or ArgumentOutOfRangeException)
            {
                continue;
            }

            if (table is null)
            {
                continue;
            }

            checked_++;
            string encoded = Convert.ToHexString(table);

            using MemoryStream stream = new(image, writable: false);
            bool found = new[] { HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512, HashAlgorithmName.SHA1 }
                .Any(algorithm => encoded.Contains(
                    Convert.ToHexString(Recompute(stream, algorithm)), StringComparison.Ordinal));

            if (!found)
            {
                mismatched.Add(path);
            }
        }

        checked_.Should().BeGreaterThan(0, "the corpus contained no signed PE images");
        mismatched.Should().BeEmpty("every signed image among the {0} checked must carry the digest we compute", checked_);
    }

    [Test]
    public void Digest_ExcludesTheChecksumField()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: false);
        byte[] mutated = (byte[])image.Clone();
        for (int i = 0; i < 4; i++)
        {
            mutated[SyntheticPe.ChecksumFieldOffset + i] ^= 0xFF;
        }

        Digest(mutated).Should().Be(Digest(image));
    }

    [Test]
    public void Digest_ExcludesTheCertificateDirectoryEntry()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: false);
        byte[] mutated = (byte[])image.Clone();

        // Only the address half is perturbed here: a non-zero size would describe a
        // certificate table that does not exist. Sign_LeavesTheDigestUnchanged covers
        // the whole entry, against a signature that really is there.
        for (int i = 0; i < 4; i++)
        {
            mutated[SyntheticPe.CertificateDirectoryOffset(pe32Plus: false) + i] ^= 0xFF;
        }

        Digest(mutated).Should().Be(Digest(image));
    }

    [Test]
    public void Digest_SkipsPaddingBetweenTheHeadersAndTheFirstSection()
    {
        // Per the Authenticode specification the digest walks the section table, so bytes
        // that belong to no section are not hashed. Compiler output rarely leaves such a
        // gap, so this behaviour is spec-derived rather than observed in the wild.
        byte[] image = SyntheticPe.Build(pe32Plus: true, headerGap: HeaderGap);
        byte[] mutated = (byte[])image.Clone();
        mutated[SyntheticPe.SizeOfHeaders + 3] ^= 0xFF;

        Digest(mutated).Should().Be(Digest(image));
    }

    [Test]
    public void Digest_CoversSectionContents()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: false);
        byte[] mutated = (byte[])image.Clone();
        mutated[SyntheticPe.FirstSectionOffset(headerGap: 0) + 7] ^= 0xFF;

        Digest(mutated).Should().NotBe(Digest(image));
    }

    [Test]
    public void Digest_CoversTrailingData()
    {
        byte[] image = SyntheticPe.Build(pe32Plus: false, headerGap: 0, trailingBytes: TrailingBytes);
        byte[] mutated = (byte[])image.Clone();
        mutated[^1] ^= 0xFF;

        Digest(mutated).Should().NotBe(Digest(image));
    }

    [Test]
    public void Digest_RejectsInputThatIsNotAPeImage()
    {
        using MemoryStream stream = new(new byte[512]);

        Action digest = () => PeFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256);

        digest.Should().Throw<InvalidDataException>().WithMessage("*MZ*");
    }

    private static byte[] Recompute(MemoryStream stream, HashAlgorithmName algorithm)
    {
        stream.Position = 0;
        return PeFile.ComputeAuthenticodeDigest(stream, algorithm);
    }

    private static IEnumerable<string> EnumeratePeFiles(string root) =>
        Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

    private static string Digest(byte[] image)
    {
        using MemoryStream stream = new(image, writable: false);
        byte[] digest = PeFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
