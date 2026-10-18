var checks = 0;
void Check(bool condition, string description)
{
    if (!condition) throw new Exception("FAILED: " + description);
    checks++;
    Console.WriteLine("PASS " + description);
}
PkiChecks.Run(Check);
DssProtocolChecks.Run(Check);
await IntegrationChecks.RunAsync(Check);
await SupplierRoundTripChecks.RunAsync(Check);
Console.WriteLine($"Passed {checks} checks.");
