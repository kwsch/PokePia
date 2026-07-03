using PokePia.Binary;

namespace PokePia.Protocol;

internal sealed class JoinRequest(uint ackId) : IPiaPayload
{
    public const byte PacketType = 1;

    public uint AckId { get; } = ackId;

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

internal sealed class JoinResponse(byte stationCount, byte hostStation, byte joiningStation, byte fragmentCount, byte fragmentIndex, byte fragmentStationInfoCount, byte fragmentBaseStationInfo, byte maxStationsActive, byte maxStationsBuffer, byte maxStationsTotal, uint updateCounter, ReadOnlyMemory<byte> stationInfoBytes, uint ackId)
{
    public const byte PacketType = 2;

    public byte StationCount { get; } = stationCount;
    public byte HostStation { get; } = hostStation;
    public byte JoiningStation { get; } = joiningStation;
    public byte FragmentCount { get; } = fragmentCount;
    public byte FragmentIndex { get; } = fragmentIndex;
    public byte FragmentStationInfoCount { get; } = fragmentStationInfoCount;
    public byte FragmentBaseStationInfo { get; } = fragmentBaseStationInfo;
    public byte MaxStationsActive { get; } = maxStationsActive;
    public byte MaxStationsBuffer { get; } = maxStationsBuffer;
    public byte MaxStationsTotal { get; } = maxStationsTotal;
    public uint UpdateCounter { get; } = updateCounter;
    public ReadOnlyMemory<byte> StationInfoBytes { get; } = stationInfoBytes;
    public uint AckId { get; } = ackId;

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
        return new JoinResponse(stationCount, hostStation, joiningStation, fragmentCount, fragmentIndex, fragmentStationInfoCount, fragmentBaseStationInfo, maxStationsActive, maxStationsBuffer, maxStationsTotal, updateCounter, stationInfoBytes, ackId);
    }
}
