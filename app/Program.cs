using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ZfTools.Data;
using ZfTools.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/Pki");
    options.Conventions.AuthorizeFolder("/Dss");
    options.Conventions.AuthorizeFolder("/Admin");
    options.Conventions.AuthorizeFolder("/History");
    options.Conventions.AllowAnonymousToPage("/Login");
});
builder.Services.AddDbContext<ToolDbContext>(options => options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=zf-tools.db"));
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, ".keyring")));
builder.Services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<PkiService>();
builder.Services.AddSingleton<CsrService>();
builder.Services.AddScoped<DssService>();
builder.Services.AddHostedService<MaintenanceService>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Login?denied=1";
    options.Cookie.Name = "zf-tools-session";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.Events.OnValidatePrincipal = async context =>
    {
        var id = context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var db = context.HttpContext.RequestServices.GetRequiredService<ToolDbContext>();
        if (!int.TryParse(id, out var userId) || !await db.Users.AnyAsync(x => x.Id == userId && x.Active))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    };
});
builder.Services.AddAuthorization();

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ToolDbContext>();
    await db.Database.EnsureCreatedAsync();
    await DatabasePatches.ApplyAsync(db);
    await SeedData.InitializeAsync(scope.ServiceProvider);
}
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.Run();
