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
    public string ModuleLabel => string.Equals(Module, "Dss", StringComparison.OrdinalIgnoreCase) ? "DSS signing" : "PKI certificates";
    public void OnGet()
    {
        Module = Normalize(Module);
        if (Request.Query["denied"] == "1")
            ModelState.AddModelError(string.Empty, "Your account is not authorized for this page. Sign in with an authorized tool account.");
    }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        Module = Normalize(Module);
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password)) { ModelState.AddModelError(string.Empty, "Enter your username and password."); return Page(); }
        if (!Enum.TryParse<ToolModule>(Module, true, out var module)) { ModelState.AddModelError(string.Empty, "Select a valid tool."); return Page(); }
        var user = await db.Users.SingleOrDefaultAsync(x => x.Username == Username.Trim() && x.Module == module, ct);
        if (user is null || !user.Active || hasher.VerifyHashedPassword(user, user.PasswordHash, Password) == PasswordVerificationResult.Failed) { ModelState.AddModelError(string.Empty, "The credentials are invalid for this tool."); return Page(); }
        user.LastLoginAtUtc = DateTime.UtcNow; db.AuditRecords.Add(new AuditRecord { UserId = user.Id, Action = "login", Details = Module }); await db.SaveChangesAsync(ct);
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.Id.ToString()), new(ClaimTypes.Name, user.Username), new(ClaimTypes.Role, user.Role.ToString()), new("module", user.Module.ToString()) };
        if (user.DssProjectId is not null) claims.Add(new Claim("projectId", user.DssProjectId.Value.ToString()));
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
        if (user.MustChangePassword) return RedirectToPage("/Account/ChangePassword");
        return RedirectToPage(user.Module == ToolModule.Pki ? "/Pki/Index" : "/Dss/Index");
    }
    private static string Normalize(string? value) => string.Equals(value, "Dss", StringComparison.OrdinalIgnoreCase) ? "Dss" : "Pki";
}
