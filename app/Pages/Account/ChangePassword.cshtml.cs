using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZfTools.Data;
using ZfTools.Services;

namespace ZfTools.Pages.Account;

public class ChangePasswordModel(ToolDbContext db, IPasswordHasher<AppUser> hasher, SessionService session) : PageModel
{
    [BindProperty] public string CurrentPassword { get; set; } = "";
    [BindProperty] public string NewPassword { get; set; } = "";
    [BindProperty] public string ConfirmPassword { get; set; } = "";
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var user = await session.CurrentAsync(User, ct);
        if (user is null) return RedirectToPage("/Login");
        CurrentPassword ??= "";
        NewPassword ??= "";
        ConfirmPassword ??= "";
        if (string.IsNullOrEmpty(CurrentPassword) || hasher.VerifyHashedPassword(user, user.PasswordHash, CurrentPassword) == PasswordVerificationResult.Failed) ModelState.AddModelError(nameof(CurrentPassword), "The current password is incorrect.");
        if (NewPassword.Length < 12) ModelState.AddModelError(nameof(NewPassword), "Use at least 12 characters.");
        if (NewPassword != ConfirmPassword) ModelState.AddModelError(nameof(ConfirmPassword), "The passwords do not match.");
        if (!ModelState.IsValid) return Page();
        user.PasswordHash = hasher.HashPassword(user, NewPassword); user.MustChangePassword = false; db.AuditRecords.Add(new AuditRecord { UserId = user.Id, Action = "change-password" }); await db.SaveChangesAsync(ct);
        return RedirectToPage(user.Module == ToolModule.Pki ? "/Pki/Index" : "/Dss/Index");
    }
}
