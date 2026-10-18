using Microsoft.EntityFrameworkCore;

namespace ZfTools.Data;

public sealed class ToolDbContext(DbContextOptions<ToolDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<PkiTemplate> PkiTemplates => Set<PkiTemplate>();
    public DbSet<DssProject> DssProjects => Set<DssProject>();
    public DbSet<DssKey> DssKeys => Set<DssKey>();
    public DbSet<SupplierConnection> SupplierConnections => Set<SupplierConnection>();
    public DbSet<PkiApplicationRecord> PkiApplications => Set<PkiApplicationRecord>();
    public DbSet<DssSigningRecord> DssSigningRecords => Set<DssSigningRecord>();
    public DbSet<AuditRecord> AuditRecords => Set<AuditRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AppUser>().HasIndex(x => new { x.Module, x.Username }).IsUnique();
        modelBuilder.Entity<DssProject>().HasIndex(x => x.Code).IsUnique();
        modelBuilder.Entity<DssKey>().HasIndex(x => new { x.DssProjectId, x.EnvironmentName, x.Name }).IsUnique();
        modelBuilder.Entity<SupplierConnection>().HasOne(x => x.Project).WithMany().HasForeignKey(x => x.DssProjectId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<PkiTemplate>().HasOne(x => x.Connection).WithMany().HasForeignKey(x => x.SupplierConnectionId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<DssKey>().HasOne(x => x.Connection).WithMany().HasForeignKey(x => x.SupplierConnectionId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<PkiApplicationRecord>().HasIndex(x => new { x.UserId, x.CreatedAtUtc });
        modelBuilder.Entity<DssSigningRecord>().HasIndex(x => new { x.UserId, x.CreatedAtUtc });
        modelBuilder.Entity<AppUser>().HasOne(x => x.DssProject).WithMany().HasForeignKey(x => x.DssProjectId).OnDelete(DeleteBehavior.SetNull);
        modelBuilder.Entity<DssKey>().HasOne(x => x.Project).WithMany(x => x.Keys).HasForeignKey(x => x.DssProjectId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<PkiApplicationRecord>().HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<DssSigningRecord>().HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
    }
}
