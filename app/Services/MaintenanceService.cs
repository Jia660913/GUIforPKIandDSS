using Microsoft.EntityFrameworkCore;
using ZfTools.Data;

namespace ZfTools.Services;

public sealed class MaintenanceService(IServiceScopeFactory scopeFactory, ILogger<MaintenanceService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<ToolDbContext>();
                await using var transaction = await db.Database.BeginTransactionAsync(stoppingToken);
                var cutoff = DateTime.UtcNow.AddYears(-1);
                await db.PkiApplications.Where(x => x.CreatedAtUtc < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.DssSigningRecords.Where(x => x.CreatedAtUtc < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.AuditRecords.Where(x => x.CreatedAtUtc < cutoff).ExecuteDeleteAsync(stoppingToken);
                await transaction.CommitAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Record-retention cleanup failed");
            }
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }
}
