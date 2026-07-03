namespace PokePia.Protocol;

internal sealed class Packet
{
    public Packet(ReadOnlyMemory<byte> data) => Data = data;

    public Packet(PiaMessage message, byte connectionId, ushort packetId)
    {
        PiaMessage = message ?? throw new ArgumentNullException(nameof(message));
        Data = ReadOnlyMemory<byte>.Empty;
        ConnectionId = connectionId;
        PacketId = packetId;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public PiaMessage? PiaMessage { get; }

    public byte ConnectionId { get; }

    public ushort PacketId { get; }

    public bool IsPia => PiaMessage is not null;

    public byte PacketType => IsPia
        ? PiaMessage!.Payload.Span[0]
        : Data.Span[0];
}
