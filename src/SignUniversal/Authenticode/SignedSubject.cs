namespace SignUniversal.Authenticode;

/// <summary>
/// The kind of file an Authenticode signature describes, which decides how
/// <c>SpcIndirectDataContent</c> names its subject.
/// </summary>
public enum SignedSubject
{
    /// <summary>A Windows PE binary, named with <c>SpcPeImageData</c>.</summary>
    PeImage,

    /// <summary>An MSI package, named with <c>SpcSipInfo</c>.</summary>
    Msi,
}
