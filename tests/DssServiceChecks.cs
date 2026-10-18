using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using ZfTools.Data;
using ZfTools.Pages.Dss;
using ZfTools.Services;

public static class DssServiceChecks
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        await using var sqlite = new SqliteConnection("Data Source=:memory:");
        await sqlite.OpenAsync();
        await using var db = new ToolDbContext(new DbContextOptionsBuilder<ToolDbContext>().UseSqlite(sqlite).Options);
        await db.Database.EnsureCreatedAsync();
        var projectA = new DssProject { Code = "A", DisplayName = "Project A" };
        var projectB = new DssProject { Code = "B", DisplayName = "Project B" };
        db.DssProjects.AddRange(projectA, projectB);
        await db.SaveChangesAsync();
        var engineer = new AppUser { Username = "engineer", Module = ToolModule.Dss, Role = UserRole.User, DssProjectId = projectA.Id };
        var administrator = new AppUser { Username = "administrator", Module = ToolModule.Dss, Role = UserRole.Admin };
        var pkiUser = new AppUser { Username = "pki", Module = ToolModule.Pki, Role = UserRole.Admin };
        var disabled = new AppUser { Username = "disabled", Module = ToolModule.Dss, Active = false, DssProjectId = projectA.Id };
        var keyA = new DssKey { DssProjectId = projectA.Id, Name = "key-a", EnvironmentName = "development" };
        var rsaKeyA = new DssKey { DssProjectId = projectA.Id, Name = "key-a-rsa", EnvironmentName = "development", SignAlgorithm = "RSA" };
        var keyB = new DssKey { DssProjectId = projectB.Id, Name = "key-b", EnvironmentName = "development" };
        db.Users.AddRange(engineer, administrator, pkiUser, disabled);
        db.DssKeys.AddRange(keyA, rsaKeyA, keyB);
        await db.SaveChangesAsync();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Suppliers:Dss:UseMock"] = "true", ["Dss:MaxInputBytes"] = "1024"
        }).Build();
        var secrets = new SupplierSecrets(new EphemeralDataProtectionProvider());
        using var clients = new SupplierHttpClientFactory(secrets);
        var service = new DssService(db, configuration, NullLogger<DssService>.Instance, clients, secrets);
        DssIndexModel Page(AppUser user) => new(db, new SessionService(db), service, configuration)
        {
            PageContext = new PageContext { HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()) }, "test")) } }
        };
        var administratorPage = Page(administrator);
        await administratorPage.OnGetAsync(default);
        check(administratorPage.IsAdmin && administratorPage.Projects.Count == 2 && administratorPage.ProjectId is null && administratorPage.Project is null,
            "DSS administrator starts with all projects available and no project implicitly selected");
        administratorPage.ProjectId = projectB.Id;
        await administratorPage.OnGetAsync(default);
        check(administratorPage.Project?.Id == projectB.Id && administratorPage.Keys.Single().Id == keyB.Id &&
            administratorPage.SupportedAlgorithms.SequenceEqual(new[] { "Ed25519" }),
            "DSS administrator can explicitly select another project's keys and their implemented algorithms");
        check(administratorPage.SelectedKeyAlgorithm is null && !administratorPage.SelectedKeyIsReady,
            "DSS does not choose an algorithm before a signing key is selected");
        administratorPage.KeyId = keyB.Id;
        check(administratorPage.SelectedKeyAlgorithm == "Ed25519" && administratorPage.SelectedKeyIsReady,
            "DSS derives the displayed algorithm and readiness from the selected project key");
        var engineerPage = Page(engineer);
        engineerPage.ProjectId = projectB.Id;
        await engineerPage.OnGetAsync(default);
        check(!engineerPage.ModelState.IsValid && engineerPage.Project is null && engineerPage.Keys.Count == 0,
            "DSS page rejects a project outside an ordinary user's assigned project");
        var unsupportedPage = Page(engineer);
        unsupportedPage.KeyId = keyA.Id; unsupportedPage.SignAlgorithm = "RSA"; unsupportedPage.InputMode = "text"; unsupportedPage.InputValue = "abc";
        await unsupportedPage.OnPostAsync(default);
        check(!unsupportedPage.ModelState.IsValid && unsupportedPage.Result is null && !await db.DssSigningRecords.AnyAsync(),
            "A forged unsupported algorithm is rejected by the page before creating a signing request");
        var rsaPage = Page(engineer);
        rsaPage.KeyId = rsaKeyA.Id; rsaPage.SignAlgorithm = "RSA"; rsaPage.InputMode = "hash"; rsaPage.InputValue = "616263";
        await rsaPage.OnPostAsync(default);
        check(rsaPage.SelectedKeyAlgorithm == "RSA" && !rsaPage.SelectedKeyIsReady && !rsaPage.ModelState.IsValid && rsaPage.Result is null && !await db.DssSigningRecords.AnyAsync(),
            "An RSA key mapping never enables the Ed25519-only signing workflow");
        check(!(await service.SignAsync(engineer, projectA.Id, "development", keyA.Id, "text", "abc", default, "RSA")).Success,
            "DSS service independently rejects an algorithm incompatible with the implemented key capability");
        var demo = await service.SignAsync(engineer, projectA.Id, "development", keyA.Id, "hash", "616263", default, "Ed25519");
        check(demo.Success && demo.Status == "demo" && demo.Signature is null, "Demo workflow never returns a fabricated supplier signature");
        var record = await db.DssSigningRecords.SingleAsync();
        check(!record.Succeeded && record.Status == "demo" && record.ProjectCodeSnapshot == "A" && record.KeyNameSnapshot == "key-a" && record.EnvironmentName == "development", "DSS history records the attempted resource and mode accurately");
        check(!(await service.SignAsync(engineer, projectB.Id, "development", keyB.Id, "text", "abc", default)).Success, "An engineer cannot sign with another project's key");
        check(!(await service.SignAsync(engineer, projectA.Id, "production", keyA.Id, "text", "abc", default)).Success, "A development key cannot be used in production");
        check(!(await service.SignAsync(pkiUser, projectA.Id, "development", keyA.Id, "text", "abc", default)).Success, "PKI accounts cannot invoke the DSS service");
        check(!(await service.SignAsync(disabled, projectA.Id, "development", keyA.Id, "text", "abc", default)).Success, "Disabled accounts cannot invoke the DSS service");
        var staleUser = new AppUser { Id = engineer.Id, Module = ToolModule.Dss, Role = UserRole.Admin };
        check(!(await service.SignAsync(staleUser, projectB.Id, "development", keyB.Id, "text", "abc", default)).Success, "DSS authorization reloads current database role rather than trusting a supplied role");
        check((await service.SignAsync(administrator, projectB.Id, "development", keyB.Id, "text", "abc", default)).Status == "demo", "DSS administrators can select an active project without an assigned default project");
        configuration["Suppliers:Dss:UseMock"] = "false";
        var blocked = await service.SignAsync(engineer, projectA.Id, "development", keyA.Id, "text", "abc", default);
        check(!blocked.Success && blocked.Status == "failed" && blocked.Error!.Contains("No supplier connection", StringComparison.Ordinal), "Real signing is blocked before network access when no supplier mapping exists");
        check(await db.DssSigningRecords.CountAsync() == 3, "Denied authorization creates no misleading successful signing records");
    }
}
