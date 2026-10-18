using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Http.Features;
using System.Net;
using ZfTools.Data;
using ZfTools.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/Pki", "PkiUser");
    options.Conventions.AuthorizeFolder("/Dss", "DssUser");
    options.Conventions.AuthorizeFolder("/Admin", "ToolAdmin");
    options.Conventions.AuthorizeFolder("/History");
    options.Conventions.AllowAnonymousToPage("/Login");
});
builder.Services.AddDbContext<ToolDbContext>(options => options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=zf-tools.db"));
var keyRingPath = builder.Configuration["DataProtection:KeyRingPath"];
builder.Services.AddDataProtection().SetApplicationName("ZfEngineeringTools")
    .PersistKeysToFileSystem(new DirectoryInfo(string.IsNullOrWhiteSpace(keyRingPath) ? Path.Combine(builder.Environment.ContentRootPath, ".keyring") : keyRingPath));
builder.Services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<PkiService>();
builder.Services.AddSingleton<CsrService>();
builder.Services.AddScoped<DssService>();
builder.Services.AddSingleton<SupplierSecrets>();
builder.Services.AddSingleton<SupplierHttpClientFactory>();
builder.Services.Configure<FormOptions>(options => { options.ValueLengthLimit = 48 * 1024 * 1024; options.MultipartBodyLengthLimit = 64 * 1024 * 1024; });
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 64 * 1024 * 1024);
if (builder.Configuration.GetValue<bool>("ReverseProxy:Enabled"))
{
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        var proxies = builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [];
        if (proxies.Length == 0) throw new InvalidOperationException("Configure at least one trusted reverse proxy address.");
        foreach (var proxy in proxies) options.KnownProxies.Add(IPAddress.Parse(proxy));
        options.ForwardLimit = 1;
    });
}
builder.Services.AddHostedService<MaintenanceService>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Login";
    options.Events.OnRedirectToAccessDenied = context =>
    {
        var module = context.Request.Path.StartsWithSegments("/Dss") ? "Dss"
            : context.Request.Path.StartsWithSegments("/Pki") ? "Pki"
            : context.HttpContext.User.FindFirst("module")?.Value ?? "Pki";
        var redirect = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(context.RedirectUri, "denied", "1");
        context.Response.Redirect(Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(redirect, "Module", module));
        return Task.CompletedTask;
    };
    options.Cookie.Name = "zf-tools-session";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.Events.OnValidatePrincipal = async context =>
    {
        var id = context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var db = context.HttpContext.RequestServices.GetRequiredService<ToolDbContext>();
        var account = int.TryParse(id, out var userId) ? await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId && x.Active) : null;
        if (account is null || context.Principal?.FindFirst("module")?.Value != account.Module.ToString() ||
            context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value != account.Role.ToString())
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    };
});
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("PkiUser", p => p.RequireAuthenticatedUser().RequireClaim("module", "Pki"));
    options.AddPolicy("DssUser", p => p.RequireAuthenticatedUser().RequireClaim("module", "Dss"));
    options.AddPolicy("ToolAdmin", p => p.RequireAuthenticatedUser().RequireRole("Admin"));
});

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ToolDbContext>();
    await db.Database.EnsureCreatedAsync();
    await DatabasePatches.ApplyAsync(db);
    await SeedData.InitializeAsync(scope.ServiceProvider);
}
if (builder.Configuration.GetValue<bool>("ReverseProxy:Enabled")) app.UseForwardedHeaders();
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
app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        if (context.Request.Path != "/Account/ChangePassword" && context.Request.Path != "/Logout" && context.Request.Path != "/Login")
        {
            var session = context.RequestServices.GetRequiredService<SessionService>();
            if ((await session.CurrentAsync(context.User, context.RequestAborted))?.MustChangePassword == true)
            {
                context.Response.Redirect("/Account/ChangePassword");
                return;
            }
        }
    }
    await next();
});
app.MapRazorPages();
app.Run();
