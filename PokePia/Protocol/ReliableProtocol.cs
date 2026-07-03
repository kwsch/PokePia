using System.Buffers.Binary;
using PokePia.Binary;

namespace PokePia.Protocol;

internal class SlidingWindowMessage(byte flags, byte streamId, ushort payloadSize, ushort sequenceId, ushort lowestPendingAck, IReadOnlyList<ulong> multicastIds, ReadOnlyMemory<byte> payload) : IPiaPayload
{
    public byte Flags { get; } = flags;
    public byte StreamId { get; } = streamId;
    public ushort PayloadSize { get; } = payloadSize;
    public ushort SequenceId { get; } = sequenceId;
    public ushort LowestPendingAck { get; } = lowestPendingAck;
    public IReadOnlyList<ulong> MulticastIds { get; } = multicastIds;
    public ReadOnlyMemory<byte> Payload { get; } = payload;

    public virtual PiaProtocol Protocol => PiaProtocol.Reliable;

    public virtual byte MessageFlags => 1;

    public static SlidingWindowMessage FromPayload(ReadOnlyMemory<byte> payload, byte flags, ushort sequenceId, ulong? destination = null)
    {
        return new SlidingWindowMessage(flags, 0, checked((ushort)payload.Length), sequenceId, 1, destination is { } multicastId ? [multicastId] : [], payload);
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
        {
            multicastIds.Add(reader.ReadUInt64BigEndian());
        }

        return new SlidingWindowMessage(flags, streamId, payloadSize, sequenceId, lowestPendingAck, multicastIds, reader.ReadSpanAndAdvance(reader.Remaining).ToArray());
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
        {
            writer.WriteUInt64BigEndian(multicastId);
        }

        writer.WriteMemory(Payload);
        return writer.ToArray();
    }
}

internal sealed class BroadcastSlidingWindowMessage(byte flags, byte streamId, ushort payloadSize, ushort sequenceId, ushort lowestPendingAck, IReadOnlyList<ulong> multicastIds, ReadOnlyMemory<byte> payload) : SlidingWindowMessage(flags, streamId, payloadSize, sequenceId, lowestPendingAck, multicastIds, payload)
{
    public override PiaProtocol Protocol => PiaProtocol.BroadcastReliable;

    public static BroadcastSlidingWindowMessage FromPayload(ReadOnlyMemory<byte> payload, byte flags, ushort sequenceId, ulong destination)
    {
        return new BroadcastSlidingWindowMessage(flags, 0, checked((ushort)payload.Length), sequenceId, 1, [destination], payload);
    }
}

internal sealed class ReliableBroadcastMessageData(uint fragmentIndex, ReadOnlyMemory<byte> data)
{
    public const byte PacketType = 0x12;

    public uint FragmentIndex { get; } = fragmentIndex;

    public ReadOnlyMemory<byte> Data { get; } = data;

    public static ReliableBroadcastMessageData Parse(ReadOnlyMemory<byte> data)
    {
        return new ReliableBroadcastMessageData(BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(8, 4)), data[12..]);
    }
}
