using PKHeX.Core;
using PokePia.Client;
using PokePia.Trade;
using System.Diagnostics;

namespace PokePia;

internal abstract class Program
{
    private static readonly CancellationTokenSource CancellationTokenSource = new();

    private static int Main()
    {
        Console.CancelKeyPress += ConsoleOnCancelKeyPress;

        try
        {
            using var client = new TradeClient(CancellationTokenSource, Log);
            client.Matchmake();
            client.EstablishConnection();
            client.JoinMesh();
            var snapshot = client.InitiateTrade();

            LogTradeStart(snapshot);

            return 0;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Client failed: {ex.Message}");
            Debug.WriteLine(ex.StackTrace);
            return 1;
        }
        finally
        {
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }

    private static void ConsoleOnCancelKeyPress(object? sender, ConsoleCancelEventArgs e) => e.Cancel = true; // Prevent immediate exit

    private static void Log(string message) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");

    private static void LogTradeStart(TradeSnapshot snapshot)
    {
        Log("All chunks received");
        Log($"Connected Player: {snapshot.TrainerCard.OT} | {snapshot.TrainerCard.TrainerID:D6}");
        Log($"  Internal IDs: {snapshot.MyStatus.TID16}/{snapshot.MyStatus.SID16}");
        Log($"  Start Date: {snapshot.TrainerCard.StartedYear}-{snapshot.TrainerCard.StartedMonth}-{snapshot.TrainerCard.StartedDay}");

        // Dump team to folder
        Log("Dumping team...");
        var dir = Path.GetDirectoryName(Environment.ProcessPath) ?? "";
        DumpParty(snapshot.Party, dir);
    }

    private static void DumpParty(IReadOnlyList<PK8> party, string dir)
    {
        for (var slot = 0; slot < party.Count; slot++)
        {
            var pk = party[slot];
            if (pk.Species == 0)
                continue;

            Log($"  Slot {slot + 1}: Species={pk.Species}, EC={pk.EncryptionConstant:X8}, PID={pk.PID:X8}, IDs={pk.TID16}/{pk.SID16}");
            Log($"    IVs: {pk.IV_HP}/{pk.IV_ATK}/{pk.IV_DEF}/{pk.IV_SPA}/{pk.IV_SPD}/{pk.IV_SPE}");
            var la = new LegalityAnalysis(pk);
            if (la.Info.PIDIV is { Type: PIDType.Xoroshiro } pidiv)
                Log($"    Raid seed detected: {pidiv.Seed64:X16}");

            var path = Path.Combine(dir, pk.FileName);
            File.WriteAllBytes(path, pk.Data);
            Log($"    Dumped {pk.FileName} ({pk.Data.Length} bytes) to {path}");
        }
    }
}
