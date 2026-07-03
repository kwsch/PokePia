using System.Buffers.Binary;
using PokePia.Binary;

namespace PokePia.Protocol;

internal class SlidingWindowMessage : IPiaPayload
{
    public required byte Flags { get; init; }
    public required byte StreamId { get; init; }
    public required ushort PayloadSize { get; init; }
    public required ushort SequenceId { get; init; }
    public required ushort LowestPendingAck { get; init; }
    public required IReadOnlyList<ulong> MulticastIds { get; init; }
    public required ReadOnlyMemory<byte> Payload { get; init; }

    public virtual PiaProtocol Protocol => PiaProtocol.Reliable;

    public virtual byte MessageFlags => 1;

    public static SlidingWindowMessage FromPayload(ReadOnlyMemory<byte> payload, byte flags, ushort sequenceId, ulong? destination = null)
    {
        return new SlidingWindowMessage
        {
            Flags = flags,
            StreamId = 0,
            PayloadSize = checked((ushort)payload.Length),
            SequenceId = sequenceId,
            LowestPendingAck = 1,
            MulticastIds = destination is { } multicastId ? [multicastId] : [],
            Payload = payload,
        };
    }

    public static SlidingWindowMessage Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        var flags = reader.ReadByte();
        var streamId = reader.ReadByte();
        var payloadSize = reader.ReadUInt16BigEndian();
        var sequenceId = reader.ReadUInt16BigEndian();
        var lowestPendingAck = reader.ReadUInt16BigEndian();
        var multicastCount = reader.ReadByte();
        var multicastIds = new List<ulong>(multicastCount);
        for (var index = 0; index < multicastCount; index++)
            multicastIds.Add(reader.ReadUInt64BigEndian());

        return new SlidingWindowMessage
        {
            Flags = flags,
            StreamId = streamId,
            PayloadSize = payloadSize,
            SequenceId = sequenceId,
            LowestPendingAck = lowestPendingAck,
            MulticastIds = multicastIds,
            Payload = reader.ReadSpanAndAdvance(reader.Remaining).ToArray(),
        };
    }

    public virtual byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(Flags);
        writer.WriteByte(StreamId);
        writer.WriteUInt16BigEndian(PayloadSize);
        writer.WriteUInt16BigEndian(SequenceId);
        writer.WriteUInt16BigEndian(LowestPendingAck);
        writer.WriteByte((byte)MulticastIds.Count);
        foreach (var multicastId in MulticastIds)
            writer.WriteUInt64BigEndian(multicastId);

        writer.WriteMemory(Payload);
        return writer.ToArray();
    }
}

internal sealed class BroadcastSlidingWindowMessage : SlidingWindowMessage
{
    public override PiaProtocol Protocol => PiaProtocol.BroadcastReliable;

    public static BroadcastSlidingWindowMessage FromPayload(ReadOnlyMemory<byte> payload, byte flags, ushort sequenceId, ulong destination) => new()
    {
        Flags = flags,
        StreamId = 0,
        PayloadSize = checked((ushort)payload.Length),
        SequenceId = sequenceId,
        LowestPendingAck = 1,
        MulticastIds = [destination],
        Payload = payload,
    };
}

internal sealed class ReliableBroadcastMessageData
{
    public const byte PacketType = 0x12;

    public required uint FragmentIndex { get; init; }
    public required ReadOnlyMemory<byte> Data { get; init; }

    public static ReliableBroadcastMessageData Parse(ReadOnlyMemory<byte> data)
    {
        return new ReliableBroadcastMessageData
        {
            FragmentIndex = BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(8, 4)),
            Data = data[12..],
        };
    }
}
