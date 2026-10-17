using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Pages;

public class LoginModel(ToolDbContext db, IPasswordHasher<AppUser> hasher) : PageModel
{
    [BindProperty(SupportsGet = true)] public string Module { get; set; } = "Pki";
    [BindProperty] public string Username { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    public string ModuleLabel => Module.Equals("Dss", StringComparison.OrdinalIgnoreCase) ? "DSS 签名工具" : "PKI 证书工具";
    public void OnGet() { Module = Normalize(Module); }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        Module = Normalize(Module);
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password)) { ModelState.AddModelError(string.Empty, "请输入账号和密码。"); return Page(); }
        if (!Enum.TryParse<ToolModule>(Module, true, out var module)) { ModelState.AddModelError(string.Empty, "请选择有效工具。"); return Page(); }
        var user = await db.Users.SingleOrDefaultAsync(x => x.Username == Username.Trim() && x.Module == module, ct);
        if (user is null || !user.Active || hasher.VerifyHashedPassword(user, user.PasswordHash, Password) == PasswordVerificationResult.Failed) { ModelState.AddModelError(string.Empty, "账号、密码或工具不正确。"); return Page(); }
        user.LastLoginAtUtc = DateTime.UtcNow; db.AuditRecords.Add(new AuditRecord { UserId = user.Id, Action = "login", Details = Module }); await db.SaveChangesAsync(ct);
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.Id.ToString()), new(ClaimTypes.Name, user.Username), new(ClaimTypes.Role, user.Role.ToString()), new("module", user.Module.ToString()) };
        if (user.DssProjectId is not null) claims.Add(new Claim("projectId", user.DssProjectId.Value.ToString()));
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
        if (user.MustChangePassword) return RedirectToPage("/Account/ChangePassword");
        return RedirectToPage(user.Module == ToolModule.Pki ? "/Pki/Index" : "/Dss/Index");
    }
    private static string Normalize(string value) => value.Equals("Dss", StringComparison.OrdinalIgnoreCase) ? "Dss" : "Pki";
}
