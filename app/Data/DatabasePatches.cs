using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ZfTools.Data;

// Additive and transactional: preserve existing mappings, accounts and operation history.
public static class DatabasePatches
{
    public static async Task ApplyAsync(ToolDbContext db)
    {
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            var connection = db.Database.GetDbConnection();
            var tx = transaction.GetDbTransaction();
            async Task Execute(string sql)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = tx; command.CommandText = sql;
                await command.ExecuteNonQueryAsync();
            }
            async Task AddColumns(string table, params (string Name, string Declaration)[] additions)
            {
                var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                await using (var command = connection.CreateCommand())
                {
                    command.Transaction = tx; command.CommandText = $"PRAGMA table_info(\"{table}\")";
                    await using var reader = await command.ExecuteReaderAsync();
                    while (await reader.ReadAsync()) columns.Add(reader.GetString(1));
                }
                foreach (var column in additions)
                    if (!columns.Contains(column.Name)) await Execute($"ALTER TABLE \"{table}\" ADD COLUMN \"{column.Name}\" {column.Declaration}");
            }
            await Execute("""
                CREATE TABLE IF NOT EXISTS SchemaChanges (Version TEXT PRIMARY KEY, AppliedAtUtc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS SupplierConnections (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, Module INTEGER NOT NULL, Name TEXT NOT NULL DEFAULT '',
                    EnvironmentName TEXT NOT NULL DEFAULT 'development', Active INTEGER NOT NULL DEFAULT 1,
                    BaseUrl TEXT NOT NULL DEFAULT '', DssProjectId INTEGER NULL REFERENCES DssProjects(Id) ON DELETE RESTRICT,
                    ClientCertificatePath TEXT NOT NULL DEFAULT '', ClientPrivateKeyPath TEXT NOT NULL DEFAULT '',
                    ClientCertificatePassword TEXT NOT NULL DEFAULT '', ServerCaChainPath TEXT NOT NULL DEFAULT '',
                    IssuerCaChainPath TEXT NOT NULL DEFAULT '', AppKey TEXT NOT NULL DEFAULT '', AppSecret TEXT NOT NULL DEFAULT '',
                    DssResponseAuthConfirmed INTEGER NOT NULL DEFAULT 0, ResponseSignatureTemplate TEXT NOT NULL DEFAULT '',
                    ResponseSignatureEncoding TEXT NOT NULL DEFAULT 'java-form', MaxInputBytes INTEGER NOT NULL DEFAULT 1048576,
                    TimeoutSeconds INTEGER NOT NULL DEFAULT 30
                );
                """);
            const string text = "TEXT NOT NULL DEFAULT ''";
            await AddColumns("SupplierConnections", ("ClientCaChainPath", text));
            await AddColumns("PkiTemplates",
                ("Archived", "INTEGER NOT NULL DEFAULT 0"),
                ("CertType", "TEXT NOT NULL DEFAULT 'diagUser'"), ("TrustGrade", "TEXT NOT NULL DEFAULT 'dev'"),
                ("DiagUserRole", "TEXT NOT NULL DEFAULT ''"),
                ("SupplierConnectionId", "INTEGER NULL REFERENCES SupplierConnections(Id) ON DELETE RESTRICT"),
                ("CsrPolicyConfirmed", "INTEGER NOT NULL DEFAULT 0"), ("VariantExactBytes", "INTEGER NOT NULL DEFAULT 0"),
                ("CommonNamePattern", text), ("UniqueIdPattern", text), ("IncludeFixedFieldsInCsr", "INTEGER NOT NULL DEFAULT 0"),
                ("VariantCritical", "INTEGER NOT NULL DEFAULT 1"), ("UniqueCritical", "INTEGER NOT NULL DEFAULT 0"),
                ("FixedFieldsCritical", "INTEGER NOT NULL DEFAULT 0"), ("ExtraExtensionsPolicy", "TEXT NOT NULL DEFAULT 'reject'"));
            await AddColumns("DssKeys", ("SupplierConnectionId", "INTEGER NULL REFERENCES SupplierConnections(Id) ON DELETE RESTRICT"),
                ("EnvironmentName", "TEXT NOT NULL DEFAULT 'development'"), ("PublicKeyPem", text),
                ("Archived", "INTEGER NOT NULL DEFAULT 0"), ("SupplierKeyAlgorithm", text), ("SupplierKeyCurve", text),
                ("SupplierKeyType", text), ("SupplierKeyStatus", text), ("SupplierKeyLength", text),
                ("SupplierMetadataUpdatedAtUtc", "TEXT NULL"));
            await AddColumns("PkiApplications", ("SupplierRequestId", text), ("TemplateNameSnapshot", text),
                ("CertProfileSnapshot", text), ("RoleSnapshot", text), ("TrustGradeSnapshot", text),
                ("ConnectionNameSnapshot", text), ("Status", "TEXT NOT NULL DEFAULT 'legacy'"));
            await AddColumns("DssSigningRecords", ("EnvironmentName", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("ProjectCodeSnapshot", text), ("KeyNameSnapshot", text), ("ConnectionNameSnapshot", text),
                ("Status", "TEXT NOT NULL DEFAULT 'legacy'"), ("SignatureVerified", "INTEGER NOT NULL DEFAULT 0"),
                ("ResponseAuthenticated", "INTEGER NOT NULL DEFAULT 0"));
            await Execute("""
                DROP INDEX IF EXISTS IX_DssKeys_DssProjectId_Name;
                CREATE UNIQUE INDEX IF NOT EXISTS IX_DssKeys_DssProjectId_EnvironmentName_Name ON DssKeys(DssProjectId,EnvironmentName,Name);
                CREATE INDEX IF NOT EXISTS IX_SupplierConnections_DssProjectId ON SupplierConnections(DssProjectId);
                CREATE INDEX IF NOT EXISTS IX_PkiTemplates_SupplierConnectionId ON PkiTemplates(SupplierConnectionId);
                CREATE INDEX IF NOT EXISTS IX_DssKeys_SupplierConnectionId ON DssKeys(SupplierConnectionId);
                CREATE INDEX IF NOT EXISTS IX_PkiApplications_UserId_CreatedAtUtc ON PkiApplications(UserId,CreatedAtUtc);
                CREATE INDEX IF NOT EXISTS IX_DssSigningRecords_UserId_CreatedAtUtc ON DssSigningRecords(UserId,CreatedAtUtc);
                UPDATE PkiApplications SET Status='demo', Succeeded=0 WHERE Status='legacy' AND CertificatePem LIKE 'DEMO ONLY%';
                UPDATE DssSigningRecords SET Status='demo', Succeeded=0 WHERE Status='legacy' AND SignatureValue LIKE 'DEMO ONLY%';
                INSERT OR IGNORE INTO SchemaChanges(Version,AppliedAtUtc) VALUES ('20261018-supplier-connections',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
                INSERT OR IGNORE INTO SchemaChanges(Version,AppliedAtUtc) VALUES ('20261018-known-dss-key-metadata',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
                """);
            // Existing role numbers and environment mappings are never reinterpreted automatically.
            await transaction.CommitAsync();
        }
        finally { await db.Database.CloseConnectionAsync(); }
    }
}
