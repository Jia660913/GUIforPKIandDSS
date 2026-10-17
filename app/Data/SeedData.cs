using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ZfTools.Data;

public static class SeedData
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<ToolDbContext>();
        var hasher = services.GetRequiredService<IPasswordHasher<AppUser>>();
        if (!await db.Users.AnyAsync())
        {
            foreach (var (module, username, display, password) in new[]
            {
                (ToolModule.Pki, "pki-admin", "PKI 管理员", "ChangeMe-PKI-2026!"),
                (ToolModule.Dss, "dss-admin", "DSS 管理员", "ChangeMe-DSS-2026!")
            })
            {
                var user = new AppUser { Module = module, Username = username, DisplayName = display, Role = UserRole.Admin, MustChangePassword = false };
                user.PasswordHash = hasher.HashPassword(user, password);
                db.Users.Add(user);
            }
        }
        if (!await db.PkiTemplates.AnyAsync())
        {
            db.PkiTemplates.AddRange(
                new PkiTemplate { DisplayName = "三级诊断证书 · 开发", CertProfile = "user-cert-dev", EnvironmentName = "development", TrustGrade = "dev", DiagUserRole = "80" },
                new PkiTemplate { DisplayName = "三级诊断证书 · 量产", CertProfile = "user-cert-prod", EnvironmentName = "production", TrustGrade = "field", DiagUserRole = "40" },
                new PkiTemplate { DisplayName = "三级诊断证书 · Claims", CertProfile = "user-cert-claims", EnvironmentName = "production", RequiresEcuUniqueId = true, RequiredFields = "ECUVariantID,ECUUniqueID", TrustGrade = "field", DiagUserRole = "02" });
        }
        if (!await db.DssProjects.AnyAsync())
        {
            var ogm = new DssProject { Code = "OGM", DisplayName = "OGM · 安全刷写" };
            var abs = new DssProject { Code = "ABS", DisplayName = "ABS · 调试接口" };
            db.DssProjects.AddRange(ogm, abs);
            db.DssKeys.AddRange(
                new DssKey { Project = ogm, Name = "ogm-signing-ed25519", SignAlgorithm = "Ed25519" },
                new DssKey { Project = abs, Name = "abs-debug-ed25519", SignAlgorithm = "Ed25519" });
        }
        await db.SaveChangesAsync();
    }
}
