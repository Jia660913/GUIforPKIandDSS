using System.Globalization;

namespace ZfTools.Data;

public sealed record PkiRole(string Name, string Hex, int ValidityDays, bool RequiresUniqueId);

public static class PkiRoleCatalog
{
    public static IReadOnlyList<PkiRole> All { get; } = Array.AsReadOnly(new[]
    {
        new PkiRole("OEM Development", "00800000", 30, true),
        new PkiRole("OEM Production", "00400000", 180, false),
        new PkiRole("OEM Field Basic", "00100000", 14, false),
        new PkiRole("OEM Field Standard", "00080000", 7, false),
        new PkiRole("OEM Field Enhanced", "00040000", 3, false),
        new PkiRole("ZF Development", "00000080", 30, true),
        new PkiRole("ZF Production", "00000040", 180, false),
        new PkiRole("ZF Field Basic", "00000010", 14, false),
        new PkiRole("ZF Field Standard", "00000008", 7, false),
        new PkiRole("ZF Field Enhanced", "00000004", 3, false),
        new PkiRole("ZF Claims", "00000002", 30, true)
    });

    public static PkiRole? Find(string? hex)
    {
        var text = hex?.Trim();
        if (text?.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true) text = text[2..];
        if (text is null || text.Length is < 1 or > 8 || !text.All(Uri.IsHexDigit) ||
            !uint.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value)) return null;
        return All.FirstOrDefault(x => x.Hex == value.ToString("X8", CultureInfo.InvariantCulture));
    }

    public static string? Normalize(string? hex) => Find(hex)?.Hex;
}
