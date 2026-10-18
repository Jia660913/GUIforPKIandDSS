using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ZfTools.Data;
using ZfTools.Pages.History;
using ZfTools.Pages.Admin;
using ZfTools.Pages.Dss;
using ZfTools.Services;

public static class IntegrationChecks
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        await MigrationAsync(check);
        await SeedArchivalAsync(check);
        await AuthorizationAndHistoryAsync(check);
        await DssServiceChecks.RunAsync(check);
    }

    private static async Task SeedArchivalAsync(Action<bool, string> check)
    {
        foreach (var includeCustomTemplate in new[] { false, true })
        {
            await using var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            await using var db = new ToolDbContext(new DbContextOptionsBuilder<ToolDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var user = new AppUser { Username = "seed-history-user", Module = ToolModule.Pki, PasswordHash = "preserved-hash" };
            var demos = new[]
            {
                new PkiTemplate { DisplayName = "三级诊断证书 · 开发", CertProfile = "user-cert-dev", EnvironmentName = "development", DiagUserRole = "80" },
                new PkiTemplate { DisplayName = "三级诊断证书 · 量产", CertProfile = "user-cert-prod", EnvironmentName = "production", DiagUserRole = "40" },
                new PkiTemplate { DisplayName = "三级诊断证书 · Claims", CertProfile = "user-cert-claims", EnvironmentName = "production", DiagUserRole = "02" }
            };
            db.Users.Add(user);
            db.PkiTemplates.AddRange(demos);
            var custom = new PkiTemplate { DisplayName = "Administrator configured template", CertProfile = "existing-customer-profile", DiagUserRole = "400000", Active = true };
            if (includeCustomTemplate) db.PkiTemplates.Add(custom);
            await db.SaveChangesAsync();
            var demoIds = demos.Select(x => x.Id).Order().ToArray();
            var history = new PkiApplicationRecord { UserId = user.Id, PkiTemplateId = demos[0].Id, RequestId = "retained-seed-history" };
            db.PkiApplications.Add(history);
            await db.SaveChangesAsync();
            using var services = new ServiceCollection().AddSingleton(db)
                .AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>().BuildServiceProvider();
            await SeedData.InitializeAsync(services);
            db.ChangeTracker.Clear();
            var templates = await db.PkiTemplates.OrderBy(x => x.Id).ToListAsync();
            check(templates.Where(x => demoIds.Contains(x.Id)).All(x => x.Archived && !x.Active) &&
                templates.Count(x => demoIds.Contains(x.Id)) == 3 &&
                (await db.PkiApplications.SingleAsync()).PkiTemplateId == demos[0].Id,
                $"Seed initialization archives old demo mappings while preserving their IDs and history ({(includeCustomTemplate ? "with custom mapping" : "legacy only")})");
            if (includeCustomTemplate)
            {
                var visible = templates.Where(x => !x.Archived).ToList();
                check(templates.Count == 4 && visible.Count == 1 && visible[0].Id == custom.Id &&
                    visible[0].CertProfile == "existing-customer-profile" && visible[0].DiagUserRole == "400000" && visible[0].Active,
                    "Seed initialization preserves administrator-defined mappings without adding replacement defaults");
            }
            else
            {
                var visible = templates.Where(x => !x.Archived).ToList();
                check(templates.Count == 25 && visible.Count == 22 && visible.All(x => !x.Active) &&
                    new[] { "development", "production" }.All(environment => PkiRoleCatalog.All.All(role =>
                        visible.Count(x => x.EnvironmentName == environment && x.DiagUserRole == role.Hex) == 1)),
                    "A legacy-demo-only database receives all 22 disabled role and environment mappings after archival");
            }
            var templateIds = templates.Select(x => x.Id).ToArray();
            await SeedData.InitializeAsync(services);
            db.ChangeTracker.Clear();
            check((await db.PkiTemplates.OrderBy(x => x.Id).Select(x => x.Id).ToArrayAsync()).SequenceEqual(templateIds),
                $"Repeated seed initialization does not add or replace mappings ({(includeCustomTemplate ? "with custom mapping" : "legacy only")})");
        }
    }

    private static async Task MigrationAsync(Action<bool, string> check)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new ToolDbContext(new DbContextOptionsBuilder<ToolDbContext>().UseSqlite(connection).Options);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE DssProjects(Id INTEGER PRIMARY KEY, Code TEXT NOT NULL, DisplayName TEXT NOT NULL, Active INTEGER NOT NULL,
                BaseUrl TEXT NOT NULL, AppKey TEXT NOT NULL, AppSecret TEXT NOT NULL, ClientCertificatePath TEXT NOT NULL, ClientCertificatePassword TEXT NOT NULL);
            CREATE TABLE Users(Id INTEGER PRIMARY KEY, Username TEXT NOT NULL, DisplayName TEXT NOT NULL, PasswordHash TEXT NOT NULL,
                Module INTEGER NOT NULL, Role INTEGER NOT NULL, Active INTEGER NOT NULL, MustChangePassword INTEGER NOT NULL,
                DssProjectId INTEGER NULL, CreatedAtUtc TEXT NOT NULL, LastLoginAtUtc TEXT NULL);
            CREATE TABLE PkiTemplates(Id INTEGER PRIMARY KEY, DisplayName TEXT NOT NULL, CertProfile TEXT NOT NULL, EnvironmentName TEXT NOT NULL,
                RequiresEcuUniqueId INTEGER NOT NULL, Active INTEGER NOT NULL, RequiredFields TEXT NOT NULL, CertType TEXT NOT NULL, TrustGrade TEXT NOT NULL, DiagUserRole TEXT NOT NULL);
            CREATE TABLE DssKeys(Id INTEGER PRIMARY KEY,DssProjectId INTEGER NOT NULL,Name TEXT NOT NULL,SignAlgorithm TEXT NOT NULL,Active INTEGER NOT NULL);
            CREATE UNIQUE INDEX IX_DssKeys_DssProjectId_Name ON DssKeys(DssProjectId,Name);
            CREATE TABLE PkiApplications(Id INTEGER PRIMARY KEY,UserId INTEGER NOT NULL,PkiTemplateId INTEGER NOT NULL,EnvironmentName TEXT NOT NULL,
                CommonName TEXT NULL,EcuVariantId TEXT NOT NULL,EcuUniqueId TEXT NULL,CsrSha256 TEXT NOT NULL,RequestId TEXT NULL,CertificatePem TEXT NULL,
                ErrorMessage TEXT NULL,Succeeded INTEGER NOT NULL,CreatedAtUtc TEXT NOT NULL);
            CREATE TABLE DssSigningRecords(Id INTEGER PRIMARY KEY,UserId INTEGER NOT NULL,DssProjectId INTEGER NOT NULL,DssKeyId INTEGER NOT NULL,
                InputMode TEXT NOT NULL,InputValue TEXT NOT NULL,InputSha256 TEXT NULL,SignAlgorithm TEXT NOT NULL,SignatureValue TEXT NULL,
                ErrorMessage TEXT NULL,Succeeded INTEGER NOT NULL,CreatedAtUtc TEXT NOT NULL);
            CREATE TABLE AuditRecords(Id INTEGER PRIMARY KEY,UserId INTEGER NULL,Action TEXT NOT NULL,Details TEXT NULL,CreatedAtUtc TEXT NOT NULL);
            INSERT INTO Users VALUES(1,'preserved-user','Existing user','unchanged-password-hash',0,0,1,0,NULL,'2026-10-01T00:00:00',NULL);
            INSERT INTO PkiTemplates VALUES(1,'Existing OEM','user-cert-dev','development',0,1,'ECUVariantID','diagUser','dev','800000');
            INSERT INTO PkiApplications VALUES(1,1,1,'development',NULL,'00',NULL,'hash','old-request','DEMO ONLY - fixture',NULL,1,'2026-10-01T00:00:00');
            """);
        await DatabasePatches.ApplyAsync(db);
        await DatabasePatches.ApplyAsync(db);
        var template = await db.PkiTemplates.SingleAsync();
        check(template.DiagUserRole == "800000", "Database upgrade never rewrites an OEM role into a ZF role");
        check(!template.CsrPolicyConfirmed && template.SupplierConnectionId is null, "Legacy supplier mappings require explicit configuration");
        check((await db.Users.SingleAsync()).PasswordHash == "unchanged-password-hash", "Database upgrade preserves existing account credentials");
        var record = await db.PkiApplications.SingleAsync();
        check(record.Status == "demo" && !record.Succeeded && record.RequestId == "old-request", "Legacy demo history is preserved and is not labeled as real issuance");
        check(!await db.SupplierConnections.AnyAsync(), "Database upgrade does not invent supplier identities or connections");
    }

    private static async Task AuthorizationAndHistoryAsync(Action<bool, string> check)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new ToolDbContext(new DbContextOptionsBuilder<ToolDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        await DatabasePatches.ApplyAsync(db);
        var alice = new AppUser { Username = "alice", Module = ToolModule.Pki };
        var bob = new AppUser { Username = "bob", Module = ToolModule.Pki };
        var admin = new AppUser { Username = "admin", Module = ToolModule.Pki, Role = UserRole.Admin };
        var dss = new AppUser { Username = "dss", Module = ToolModule.Dss };
        var template = new PkiTemplate { DisplayName = "Renamed template", CertProfile = "real-profile", DiagUserRole = "40", TrustGrade = "dev" };
        db.Users.AddRange(alice, bob, admin, dss); db.PkiTemplates.Add(template);
        await db.SaveChangesAsync();
        for (var i = 0; i < 27; i++) db.PkiApplications.Add(new PkiApplicationRecord
        {
            UserId = alice.Id, PkiTemplateId = template.Id, TemplateNameSnapshot = "Original template", Status = "succeeded", Succeeded = true,
            CertificatePem = "test-only-public-result", RequestId = "req-" + i, CreatedAtUtc = DateTime.UtcNow.AddMinutes(-i)
        });
        var foreign = new PkiApplicationRecord { UserId = bob.Id, PkiTemplateId = template.Id, Status = "succeeded", Succeeded = true, CertificatePem = "private-to-bob" };
        var expired = new PkiApplicationRecord { UserId = alice.Id, PkiTemplateId = template.Id, CreatedAtUtc = DateTime.UtcNow.AddYears(-2) };
        db.PkiApplications.AddRange(foreign, expired); await db.SaveChangesAsync();
        var session = new SessionService(db);
        HistoryModel Page(AppUser user) => new(db, session)
        {
            PageContext = new PageContext { HttpContext = new DefaultHttpContext { User = Principal(user) } }
        };
        var history = Page(alice);
        await history.OnGetAsync(default);
        check(history.Items.Count == 25 && history.TotalCount == 27 && history.PageCount == 2, "History is paginated and scoped to the current user and retention period");
        check(history.Items.All(x => x.Subject == "Original template"), "History keeps operation-time template snapshots after mapping edits");
        history.PageNumber = 2; await history.OnGetAsync(default);
        check(history.Items.Count == 2, "History page two exposes the remaining records");
        history.DetailId = foreign.Id;
        check(await history.OnGetAsync(default) is NotFoundResult, "History details reject another user's record ID");
        check(await history.OnGetDownloadAsync(foreign.Id, "certificate", default) is NotFoundResult, "Result download rejects another user's record ID");
        check(await Page(dss).OnGetDownloadAsync(foreign.Id, "certificate", default) is NotFoundResult, "DSS sessions cannot download PKI results");
        var adminHistory = Page(admin); await adminHistory.OnGetAsync(default);
        check(adminHistory.TotalCount == 28, "PKI administrators can inspect all retained PKI records");
        var own = await db.PkiApplications.FirstAsync(x => x.UserId == alice.Id && x.Status == "succeeded");
        check(await Page(alice).OnGetDownloadAsync(own.Id, "certificate", default) is FileContentResult, "Authorized users can download their verified certificate");
        own.Status = "unknown"; own.Succeeded = false; await db.SaveChangesAsync();
        check(await Page(alice).OnGetDownloadAsync(own.Id, "certificate", default) is NotFoundResult, "Unverified outcomes are not downloadable as successful certificates");
        var secrets = new SupplierSecrets(new EphemeralDataProtectionProvider());
        using var clients = new SupplierHttpClientFactory(secrets);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Suppliers:Pki:UseMock"] = "true" }).Build();
        var administration = new AdminModel(db, session, new PasswordHasher<AppUser>(), secrets,
            new DssService(db, config, NullLogger<DssService>.Instance, clients, secrets))
        {
            PageContext = new PageContext { HttpContext = new DefaultHttpContext { User = Principal(admin) } },
            TempData = new TempDataDictionary(new DefaultHttpContext(), new TestTempDataProvider()),
            ConnectionInput = new ConnectionForm { Name = "Disabled draft", Active = false, ClientCertificatePassword = "test-only-old-password" }
        };
        await administration.OnPostSaveConnectionAsync(default);
        var saved = await db.SupplierConnections.SingleAsync();
        check(secrets.Unprotect(saved.ClientCertificatePassword) == "test-only-old-password", "Administrator stores connection passwords protected at rest");
        administration.ConnectionInput = new ConnectionForm { Id = saved.Id, Name = saved.Name, Active = false };
        await administration.OnPostSaveConnectionAsync(default);
        check(secrets.Unprotect(saved.ClientCertificatePassword) == "test-only-old-password", "Blank password edits preserve the existing connection password");
        administration.ConnectionInput = new ConnectionForm { Id = saved.Id, Name = saved.Name, Active = false, ClearCertificatePassword = true };
        await administration.OnPostSaveConnectionAsync(default);
        check(saved.ClientCertificatePassword == "", "Explicit clearing supports switching to a passwordless identity");
        var project = new DssProject { Code = "RETENTION", DisplayName = "Retention test" };
        var signingKey = new DssKey { Project = project, Name = "retention-key" };
        var oldSignature = new DssSigningRecord { UserId = dss.Id, Project = project, Key = signingKey, CreatedAtUtc = DateTime.UtcNow.AddYears(-2),
            Status = "succeeded", Succeeded = true, SignatureVerified = true, ResponseAuthenticated = true, SignatureValue = new string('a',128) };
        db.DssSigningRecords.Add(oldSignature); await db.SaveChangesAsync();
        var signingService = new DssService(db, config, NullLogger<DssService>.Instance, clients, secrets);
        var signingPage = new DssIndexModel(db, session, signingService, config)
        { PageContext = new PageContext { HttpContext = new DefaultHttpContext { User = Principal(dss) } } };
        check(await signingPage.OnGetSignatureAsync(oldSignature.Id, default) is NotFoundResult, "Direct DSS downloads enforce the one-year retention boundary");
        var pki = new PkiService(db, config, clients, NullLogger<PkiService>.Instance);
        var denied = await pki.ApplyAsync(dss, template, "not a CSR", "00", null, null, "127.0.0.1", default);
        check(!denied.Success && denied.Error!.Contains("not authorized"), "PKI service blocks DSS users before processing any CSR");
        alice.Active = false; await db.SaveChangesAsync();
        denied = await pki.ApplyAsync(alice, template, "not a CSR", "00", null, null, "127.0.0.1", default);
        check(!denied.Success, "PKI service rechecks account activation against the database");
    }

    private static ClaimsPrincipal Principal(AppUser user) => new(new ClaimsIdentity(new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), new Claim("module", user.Module.ToString()),
        new Claim(ClaimTypes.Role, user.Role.ToString())
    }, "test"));

    private sealed class TestTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }
}
