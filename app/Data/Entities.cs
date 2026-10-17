namespace ZfTools.Data;

public enum ToolModule { Pki, Dss }
public enum UserRole { Admin, User }

public sealed class AppUser
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public ToolModule Module { get; set; }
    public UserRole Role { get; set; }
    public bool Active { get; set; } = true;
    public bool MustChangePassword { get; set; }
    public int? DssProjectId { get; set; }
    public DssProject? DssProject { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAtUtc { get; set; }
}

public sealed class PkiTemplate
{
    public int Id { get; set; }
    public string DisplayName { get; set; } = "";
    public string CertProfile { get; set; } = "";
    public string EnvironmentName { get; set; } = "development";
    public bool RequiresEcuUniqueId { get; set; }
    public bool Active { get; set; } = true;
    public string RequiredFields { get; set; } = "ECUVariantID";
    public string CertType { get; set; } = "diagUser";
    public string TrustGrade { get; set; } = "dev";
    public string DiagUserRole { get; set; } = "80";
}

public sealed class DssProject
{
    public int Id { get; set; }
    public string Code { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool Active { get; set; } = true;
    public string BaseUrl { get; set; } = "";
    public string AppKey { get; set; } = "";
    public string AppSecret { get; set; } = "";
    public string ClientCertificatePath { get; set; } = "";
    public string ClientCertificatePassword { get; set; } = "";
    public List<DssKey> Keys { get; set; } = [];
}

public sealed class DssKey
{
    public int Id { get; set; }
    public int DssProjectId { get; set; }
    public DssProject? Project { get; set; }
    public string Name { get; set; } = "";
    public string SignAlgorithm { get; set; } = "Ed25519";
    public bool Active { get; set; } = true;
}

public sealed class PkiApplicationRecord
{
    public long Id { get; set; }
    public int UserId { get; set; }
    public AppUser? User { get; set; }
    public int PkiTemplateId { get; set; }
    public PkiTemplate? Template { get; set; }
    public string EnvironmentName { get; set; } = "development";
    public string? CommonName { get; set; }
    public string EcuVariantId { get; set; } = "";
    public string? EcuUniqueId { get; set; }
    public string CsrSha256 { get; set; } = "";
    public string? RequestId { get; set; }
    public string? CertificatePem { get; set; }
    public string? ErrorMessage { get; set; }
    public bool Succeeded { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public sealed class DssSigningRecord
{
    public long Id { get; set; }
    public int UserId { get; set; }
    public AppUser? User { get; set; }
    public int DssProjectId { get; set; }
    public DssProject? Project { get; set; }
    public int DssKeyId { get; set; }
    public DssKey? Key { get; set; }
    public string InputMode { get; set; } = "hash";
    public string InputValue { get; set; } = "";
    public string? InputSha256 { get; set; }
    public string SignAlgorithm { get; set; } = "Ed25519";
    public string? SignatureValue { get; set; }
    public string? ErrorMessage { get; set; }
    public bool Succeeded { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public sealed class AuditRecord
{
    public long Id { get; set; }
    public int? UserId { get; set; }
    public string Action { get; set; } = "";
    public string? Details { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
