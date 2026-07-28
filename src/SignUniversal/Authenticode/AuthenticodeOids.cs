namespace SignUniversal.Authenticode;

/// <summary>
/// Object identifiers used by Authenticode, plus digest-algorithm OID mapping.
/// </summary>
public static class AuthenticodeOids
{
    /// <summary>SPC_INDIRECT_DATA_OBJID - the SignedData content type for Authenticode.</summary>
    public const string SpcIndirectDataObjId = "1.3.6.1.4.1.311.2.1.4";

    /// <summary>SPC_PE_IMAGE_DATAOBJ - identifies the signed subject as a PE image.</summary>
    public const string SpcPeImageDataObjId = "1.3.6.1.4.1.311.2.1.15";

    /// <summary>SPC_SIPINFO_OBJID - identifies the signed subject by its SIP, as MSI does.</summary>
    public const string SpcSipInfoObjId = "1.3.6.1.4.1.311.2.1.30";

    /// <summary>SPC_STATEMENT_TYPE_OBJID - the signed attribute naming the purpose of the signature.</summary>
    public const string SpcStatementTypeObjId = "1.3.6.1.4.1.311.2.1.11";

    /// <summary>SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID - what signtool puts in that attribute.</summary>
    public const string IndividualCodeSigningObjId = "1.3.6.1.4.1.311.2.1.21";

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to its digest-algorithm OID.</summary>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>The dotted OID string.</returns>
    public static string DigestOid(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA256" => "2.16.840.1.101.3.4.2.1",
        "SHA384" => "2.16.840.1.101.3.4.2.2",
        "SHA512" => "2.16.840.1.101.3.4.2.3",
        "SHA1" => "1.3.14.3.2.26",
        _ => throw new NotSupportedException($"Unsupported hash algorithm '{hashAlgorithm.Name}'."),
    };
}
