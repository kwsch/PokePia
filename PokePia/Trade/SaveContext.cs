using PKHeX.Core;

namespace PokePia.Trade;

internal sealed class SaveContext
{
    public SAV8SWSH Save { get; } = new();

    public TradeSnapshot BuildSnapshot(TradeBroadcastPayload payload)
    {
        CopyToBlock(payload.MyStatusMemory.Span, Save.MyStatus.Data);
        CopyToBlock(payload.TrainerCardMemory.Span, Save.TrainerCard.Data);

        return new TradeSnapshot(payload.CreateParty(), Save, Save.MyStatus, Save.TrainerCard);
    }

    private static void CopyToBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        source[..Math.Min(source.Length, destination.Length)].CopyTo(destination);
    }
}

internal sealed class TradeSnapshot(IReadOnlyList<PK8> party, SAV8SWSH save, MyStatus8 myStatusBlock, TrainerCard8 trainerCardBlock)
{
    public IReadOnlyList<PK8> Party { get; } = party;

    public SAV8SWSH Save { get; } = save;

    public MyStatus8 MyStatus { get; } = myStatusBlock;

    public TrainerCard8 TrainerCard { get; } = trainerCardBlock;
}
