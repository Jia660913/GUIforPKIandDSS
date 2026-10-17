using Microsoft.EntityFrameworkCore;

namespace ZfTools.Data;

public static class DatabasePatches
{
    public static async Task ApplyAsync(ToolDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        await connection.OpenAsync();
        try
        {
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "PRAGMA table_info('PkiTemplates')";
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync()) columns.Add(reader.GetString(1));
            }
            foreach (var (name, sqlType, defaultValue) in new[]
            {
                ("CertType", "TEXT", "'diagUser'"),
                ("TrustGrade", "TEXT", "'dev'"),
                ("DiagUserRole", "TEXT", "'800000'")
            })
            {
                if (columns.Contains(name)) continue;
                await using var command = connection.CreateCommand();
                command.CommandText = $"ALTER TABLE PkiTemplates ADD COLUMN {name} {sqlType} NOT NULL DEFAULT {defaultValue}";
                await command.ExecuteNonQueryAsync();
            }
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "UPDATE PkiTemplates SET DiagUserRole = CASE WHEN CertProfile = 'user-cert-dev' THEN '80' WHEN CertProfile = 'user-cert-prod' THEN '40' WHEN CertProfile = 'user-cert-claims' THEN '02' ELSE DiagUserRole END WHERE CertProfile IN ('user-cert-dev', 'user-cert-prod', 'user-cert-claims') AND DiagUserRole IN ('800000', '020000')";
                await command.ExecuteNonQueryAsync();
            }
        }
        finally { await connection.CloseAsync(); }
    }
}
