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
/// The expected digests come from the independent reference implementation in
/// <c>tools/authenticode-digest-reference.py</c>, which was cross-checked against
/// several hundred Microsoft-signed binaries (PE32 and PE32+) by recomputing each
/// one's digest and finding it inside its own embedded signature.
/// </remarks>
public sealed class PeDigestTests
{
    private const int TrailingBytes = 5;
    private const int HeaderGap = 0x200;

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

    private static string Digest(byte[] image)
    {
        using MemoryStream stream = new(image, writable: false);
        byte[] digest = PeFile.ComputeAuthenticodeDigest(stream, HashAlgorithmName.SHA256);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
