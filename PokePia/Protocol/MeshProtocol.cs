using PokePia.Binary;

namespace PokePia.Protocol;

internal sealed class JoinRequest : IPiaPayload
{
    public const byte PacketType = 1;

    public required uint AckId { get; init; }
    public Ack Ack() => new() { AckId = AckId };

    public PiaProtocol Protocol => PiaProtocol.Mesh;
    public byte MessageFlags => 9;

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WriteByte(253);
        writer.WriteUInt32BigEndian(AckId);
        return writer.ToArray();
    }
}

internal sealed class JoinResponse
{
    public const byte PacketType = 2;

    public required byte StationCount { get; init; }
    public required byte HostStation { get; init; }
    public required byte JoiningStation { get; init; }
    public required byte FragmentCount { get; init; }
    public required byte FragmentIndex { get; init; }
    public required byte FragmentStationInfoCount { get; init; }
    public required byte FragmentBaseStationInfo { get; init; }
    public required byte MaxStationsActive { get; init; }
    public required byte MaxStationsBuffer { get; init; }
    public required byte MaxStationsTotal { get; init; }
    public required uint UpdateCounter { get; init; }
    public required ReadOnlyMemory<byte> StationInfoBytes { get; init; }
    public required uint AckId { get; init; }
    public Ack Ack() => new() { AckId = AckId };

    public static JoinResponse Parse(ReadOnlyMemory<byte> data)
    {
        var span = data.Span;
        var stationInfoBytesLength = data.Length - 20;
        var reader = new BinarySpanReader(span);
        var messageType = reader.ReadByte();
        if (messageType != PacketType)
            throw new InvalidOperationException($"Unexpected join response type {messageType}.");

        var stationCount = reader.ReadByte();
        var hostStation = reader.ReadByte();
        var joiningStation = reader.ReadByte();
        var fragmentCount = reader.ReadByte();
        var fragmentIndex = reader.ReadByte();
        var fragmentStationInfoCount = reader.ReadByte();
        var fragmentBaseStationInfo = reader.ReadByte();
        var maxStationsActive = reader.ReadByte();
        var maxStationsBuffer = reader.ReadByte();
        var maxStationsTotal = reader.ReadByte();
        reader.ReadByte();
        var updateCounter = reader.ReadUInt32BigEndian();
        var stationInfoBytes = reader.ReadSpanAndAdvance(stationInfoBytesLength).ToArray();
        var ackId = reader.ReadUInt32BigEndian();
        return new JoinResponse
        {
            StationCount = stationCount,
            HostStation = hostStation,
            JoiningStation = joiningStation,
            FragmentCount = fragmentCount,
            FragmentIndex = fragmentIndex,
            FragmentStationInfoCount = fragmentStationInfoCount,
            FragmentBaseStationInfo = fragmentBaseStationInfo,
            MaxStationsActive = maxStationsActive,
            MaxStationsBuffer = maxStationsBuffer,
            MaxStationsTotal = maxStationsTotal,
            UpdateCounter = updateCounter,
            StationInfoBytes = stationInfoBytes,
            AckId = ackId,
        };
    }
}
