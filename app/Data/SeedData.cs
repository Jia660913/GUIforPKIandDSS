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
                (ToolModule.Pki, "pki-admin", "PKI administrator", "ZfPki-Tool-2026!"),
                (ToolModule.Dss, "dss-admin", "DSS administrator", "ZfDss-Tool-2026!")
            })
            {
                var user = new AppUser { Module = module, Username = username, DisplayName = display, Role = UserRole.Admin, MustChangePassword = false };
                user.PasswordHash = hasher.HashPassword(user, password);
                db.Users.Add(user);
            }
        }
        if (!await db.DssProjects.AnyAsync())
        {
            var ogm = new DssProject { Code = "OGM", DisplayName = "OGM software signing" };
            var abs = new DssProject { Code = "ABS", DisplayName = "ABS software signing" };
            db.DssProjects.AddRange(ogm, abs);
            // Supplier key names must be registered from an existing authorized project; never invent them.
        }
        // Localize only the original default labels; retain administrator-defined names and all supplier mappings.
        var labels = new Dictionary<string, string>
        {
            ["PKI 管理员"] = "PKI administrator",
            ["DSS 管理员"] = "DSS administrator",
            ["OGM 工程师"] = "OGM engineer",
            ["三级诊断证书 · 开发"] = "Diagnostic user certificate",
            ["三级诊断证书 · 量产"] = "Diagnostic user certificate",
            ["三级诊断证书 · Claims"] = "Claims user certificate",
            ["OGM · 安全刷写"] = "OGM software signing",
            ["ABS · 调试接口"] = "ABS software signing"
        };
        var oldLabels = labels.Keys.ToArray();
        foreach (var user in await db.Users.Where(x => oldLabels.Contains(x.DisplayName)).ToListAsync())
            user.DisplayName = labels[user.DisplayName];
        foreach (var template in await db.PkiTemplates.Where(x => oldLabels.Contains(x.DisplayName)).ToListAsync())
            template.DisplayName = labels[template.DisplayName];
        foreach (var project in await db.DssProjects.Where(x => oldLabels.Contains(x.DisplayName)).ToListAsync())
            project.DisplayName = labels[project.DisplayName];
        // Retire only the original unconnected demo fixtures; keep their IDs for history references.
        var existingTemplates = await db.PkiTemplates.ToListAsync();
        foreach (var template in existingTemplates.Where(x => !x.Archived && x.SupplierConnectionId == null))
        {
            var isDemo = (template.DisplayName, template.CertProfile, template.EnvironmentName, template.DiagUserRole) switch
            {
                ("Diagnostic user certificate", "user-cert-dev", "development", "80") => true,
                ("Diagnostic user certificate", "user-cert-prod", "production", "40") => true,
                ("Claims user certificate", "user-cert-claims", "production", "02") => true,
                _ => false
            };
            if (isDemo) { template.Active = false; template.Archived = true; }
        }
        // Check the tracked state after retirement so a database containing only old demos gets the role catalog.
        if (!existingTemplates.Any(x => !x.Archived))
        {
            foreach (var environment in new[] { "development", "production" })
                foreach (var role in PkiRoleCatalog.All)
                    db.PkiTemplates.Add(new PkiTemplate
                    {
                        DisplayName = role.Name, CertProfile = "", EnvironmentName = environment,
                        TrustGrade = environment == "production" ? "field" : "dev", DiagUserRole = role.Hex,
                        RequiresEcuUniqueId = role.RequiresUniqueId,
                        RequiredFields = role.RequiresUniqueId ? "ECUVariantID,ECUUniqueID" : "ECUVariantID",
                        CsrPolicyConfirmed = false, Active = false
                    });
        }
        foreach (var key in await db.DssKeys.Include(x => x.Project).Where(x => !x.Archived && x.SupplierConnectionId == null && x.PublicKeyPem == "").ToListAsync())
        {
            if (key.EnvironmentName == "development" &&
                ((key.Project?.Code == "OGM" && key.Name == "ogm-signing-ed25519") ||
                 (key.Project?.Code == "ABS" && key.Name == "abs-debug-ed25519")))
            {
                key.Active = false; key.Archived = true;
            }
        }
        await db.SaveChangesAsync();
    }
}
