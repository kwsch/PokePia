using System.Buffers.Binary;
using PKHeX.Core;

namespace PokePia.Trade;

internal sealed class TradeBroadcastPayload
{
    public const int PayloadLength = 3456;
    private const int PartySlotSize = 344;
    private const int PartyOffset = 0;
    private const int PartyCountOffset = PartyOffset + (PartySlotSize * 6);
    private const int MyStatusOffset = PartyCountOffset + 4;
    private const int MyStatusLength = 272;
    private const int TrainerCardOffset = MyStatusOffset + MyStatusLength;
    private const int TrainerCardLength = 456;

    private readonly ReadOnlyMemory<byte> _memory;

    public TradeBroadcastPayload(ReadOnlyMemory<byte> memory)
    {
        if (memory.Length != PayloadLength)
            throw new ArgumentException($"Expected {PayloadLength} bytes for trade payload, got {memory.Length}.", nameof(memory));

        _memory = memory;
    }

    public uint PartyCount => BinaryPrimitives.ReadUInt32LittleEndian(_memory.Span.Slice(PartyCountOffset, 4));

    public ReadOnlyMemory<byte> MyStatusMemory => _memory.Slice(MyStatusOffset, MyStatusLength);

    public ReadOnlyMemory<byte> TrainerCardMemory => _memory.Slice(TrainerCardOffset, TrainerCardLength);

    public IReadOnlyList<PK8> CreateParty()
    {
        var count = (int)Math.Min(6, PartyCount);
        var party = new List<PK8>(count);
        for (var slot = 0; slot < count; slot++)
        {
            var raw = _memory.Slice(PartyOffset + (slot * PartySlotSize), PartySlotSize).ToArray();
            party.Add(new PK8(raw.AsMemory()));
        }

        return party;
    }
}
