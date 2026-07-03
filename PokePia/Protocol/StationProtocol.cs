using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using PokePia.Binary;

namespace PokePia.Protocol;

internal sealed class StationLocation : IByteSerializable
{
    public StationLocation(byte publicAddressSize, byte privateAddressSize, IPEndPoint publicAddress, IPEndPoint privateAddress, IPEndPoint relayAddress, ulong constantId, uint variableId, uint serviceVariableId, byte flags, byte natLocation, byte probeInit, bool isPrivateAddressAvailable)
    {
        PublicAddressSize = publicAddressSize;
        PrivateAddressSize = privateAddressSize;
        PublicAddress = publicAddress;
        PrivateAddress = privateAddress ?? throw new ArgumentNullException(nameof(privateAddress));
        RelayAddress = relayAddress ?? throw new ArgumentNullException(nameof(relayAddress));
        ConstantId = constantId;
        VariableId = variableId;
        ServiceVariableId = serviceVariableId;
        Flags = flags;
        NatLocation = natLocation;
        ProbeInit = probeInit;
        IsPrivateAddressAvailable = isPrivateAddressAvailable;
    }

    public byte PublicAddressSize { get; }
    public byte PrivateAddressSize { get; }
    public IPEndPoint PublicAddress { get; }
    public IPEndPoint PrivateAddress { get; }
    public IPEndPoint RelayAddress { get; }
    public ulong ConstantId { get; }
    public uint VariableId { get; }
    public uint ServiceVariableId { get; }
    public byte Flags { get; }
    public byte NatLocation { get; }
    public byte ProbeInit { get; }
    public bool IsPrivateAddressAvailable { get; }

    public static StationLocation FromAddress(IPEndPoint address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 station addresses are supported.", nameof(address));

        var addressBytes = address.Address.GetAddressBytes();
        var ipValue = BinaryPrimitives.ReadUInt32BigEndian(addressBytes);
        var variableIdBytes = RandomNumberGenerator.GetBytes(sizeof(uint));
        return new StationLocation(
            2,
            6,
            new IPEndPoint(IPAddress.Any, 0),
            address,
            new IPEndPoint(IPAddress.Any, 0),
            ((ulong)ipValue << 32) | (uint)address.Port,
            BinaryPrimitives.ReadUInt32LittleEndian(variableIdBytes),
            ((ipValue & 0xFFFFu) << 16) | (uint)address.Port,
            0,
            0,
            0,
            true);
    }

    public static StationLocation Parse(ReadOnlyMemory<byte> data)
    {
        var span = data.Span;
        if (span.Length < 2)
            throw new InvalidOperationException("Station location payload is too small.");

        var publicAddressSize = span[0];
        var privateAddressSize = span[1];
        var reader = new BinarySpanReader(span);
        reader.Advance(2);
        var publicIpBytes = reader.ReadSpanAndAdvance(publicAddressSize - 2).ToArray();
        var publicPort = reader.ReadUInt16BigEndian();
        var privateIp = new IPAddress(reader.ReadSpanAndAdvance(privateAddressSize - 2));
        var privatePort = reader.ReadUInt16BigEndian();
        var relayIp = new IPAddress(reader.ReadSpanAndAdvance(4));
        var relayPort = reader.ReadUInt16BigEndian();
        var constantId = reader.ReadUInt64BigEndian();
        var variableId = reader.ReadUInt32BigEndian();
        var serviceVariableId = reader.ReadUInt32BigEndian();
        var flags = reader.ReadByte();
        var natLocation = reader.ReadByte();
        var probeInit = reader.ReadByte();
        var isPrivateAddressAvailable = reader.ReadBoolean();
        return new StationLocation(
            publicAddressSize,
            privateAddressSize,
            publicAddressSize > 2 ? new IPEndPoint(new IPAddress(publicIpBytes), publicPort) : new IPEndPoint(IPAddress.Any, publicPort),
            new IPEndPoint(privateIp, privatePort),
            new IPEndPoint(relayIp, relayPort),
            constantId,
            variableId,
            serviceVariableId,
            flags,
            natLocation,
            probeInit,
            isPrivateAddressAvailable);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PublicAddressSize);
        writer.WriteByte(PrivateAddressSize);
        if (PublicAddressSize > 2)
            writer.WriteIPAddress(PublicAddress.Address);

        writer.WriteUInt16BigEndian((ushort)PublicAddress.Port);
        writer.WriteIPAddress(PrivateAddress.Address);
        writer.WriteUInt16BigEndian((ushort)PrivateAddress.Port);
        writer.WriteIPAddress(RelayAddress.Address);
        writer.WriteUInt16BigEndian((ushort)RelayAddress.Port);
        writer.WriteUInt64BigEndian(ConstantId);
        writer.WriteUInt32BigEndian(VariableId);
        writer.WriteUInt32BigEndian(ServiceVariableId);
        writer.WriteByte(Flags);
        writer.WriteByte(NatLocation);
        writer.WriteByte(ProbeInit);
        writer.WriteBoolean(IsPrivateAddressAvailable);
        return writer.ToArray();
    }
}

internal sealed class ConnectionRequest(byte connectionId, byte version, bool isInverseConnection, ulong targetConstantId, uint targetVariableId, byte inverseConnectionId, StationLocation stationLocation, uint ackId) : IPiaPayload
{
    public const byte PacketType = 1;

    public byte ConnectionId { get; } = connectionId;
    public byte Version { get; } = version;
    public bool IsInverseConnection { get; } = isInverseConnection;
    public ulong TargetConstantId { get; } = targetConstantId;
    public uint TargetVariableId { get; } = targetVariableId;
    public byte InverseConnectionId { get; } = inverseConnectionId;
    public StationLocation StationLocation { get; } = stationLocation ?? throw new ArgumentNullException(nameof(stationLocation));
    public uint AckId { get; } = ackId;

    public PiaProtocol Protocol => PiaProtocol.Station;

    public byte MessageFlags => 1;

    public static ConnectionRequest Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        reader.ReadByte();
        var connectionId = reader.ReadByte();
        var version = reader.ReadByte();
        var isInverseConnection = reader.ReadBoolean();
        var targetConstantId = reader.ReadUInt64BigEndian();
        var targetVariableId = reader.ReadUInt32BigEndian();
        var inverseConnectionId = reader.ReadByte();
        var ackId = BinaryPrimitives.ReadUInt32BigEndian(data.Span[^4..]);
        var stationLocation = StationLocation.Parse(data.Slice(17, data.Length - 21));
        return new ConnectionRequest(connectionId, version, isInverseConnection, targetConstantId, targetVariableId, inverseConnectionId, stationLocation, ackId);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WriteByte(ConnectionId);
        writer.WriteByte(Version);
        writer.WriteBoolean(IsInverseConnection);
        writer.WriteUInt64BigEndian(TargetConstantId);
        writer.WriteUInt32BigEndian(TargetVariableId);
        writer.WriteByte(InverseConnectionId);
        writer.WriteMemory(StationLocation.ToArray());
        writer.WriteUInt32BigEndian(AckId);
        return writer.ToArray();
    }
}

internal sealed class StationPlayerInfo(string playerName, byte playerNameEncodingType, string accountName, byte accountNameEncodingType, byte language, ReadOnlyMemory<byte> playHistoryRegistrationKey, ulong principalId) : IByteSerializable
{
    public string PlayerName { get; } = playerName;
    public byte PlayerNameEncodingType { get; } = playerNameEncodingType;
    public string AccountName { get; } = accountName;
    public byte AccountNameEncodingType { get; } = accountNameEncodingType;
    public byte Language { get; } = language;
    public ReadOnlyMemory<byte> PlayHistoryRegistrationKey { get; } = playHistoryRegistrationKey;
    public ulong PrincipalId { get; } = principalId;

    public static StationPlayerInfo Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        var playerNameBytes = reader.ReadSpanAndAdvance(80).ToArray();
        var playerNameEncodingType = reader.ReadByte();
        var accountNameBytes = reader.ReadSpanAndAdvance(40).ToArray();
        var accountNameEncodingType = reader.ReadByte();
        var language = reader.ReadByte();
        var playHistoryRegistrationKey = reader.ReadSpanAndAdvance(64).ToArray();
        var principalId = reader.ReadUInt64BigEndian();
        return new StationPlayerInfo(
            Decode(playerNameBytes, playerNameEncodingType),
            playerNameEncodingType,
            Decode(accountNameBytes, accountNameEncodingType),
            accountNameEncodingType,
            language,
            playHistoryRegistrationKey,
            principalId);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.Write(Encode(PlayerName, PlayerNameEncodingType, 80));
        writer.WriteByte(PlayerNameEncodingType);
        writer.Write(Encode(AccountName, AccountNameEncodingType, 40));
        writer.WriteByte(AccountNameEncodingType);
        writer.WriteByte(Language);
        writer.WriteMemory(PlayHistoryRegistrationKey);
        writer.WritePadding(Math.Max(0, 64 - PlayHistoryRegistrationKey.Length));
        writer.WriteUInt64BigEndian(PrincipalId);
        return writer.ToArray();
    }

    private static string Decode(ReadOnlySpan<byte> bytes, byte encodingType) => encodingType switch
    {
        1 => Encoding.UTF8.GetString(bytes).TrimEnd('\0'),
        2 => Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
        _ => string.Empty,
    };

    private static byte[] Encode(string value, byte encodingType, int fieldLength)
    {
        var bytes = encodingType switch
        {
            1 => Encoding.UTF8.GetBytes(value),
            2 => Encoding.Unicode.GetBytes(value),
            _ => [],
        };

        if (bytes.Length > fieldLength)
        {
            throw new ArgumentException($"Encoded string exceeds field length {fieldLength}.", nameof(value));
        }

        var buffer = new byte[fieldLength];
        bytes.CopyTo(buffer, 0);
        return buffer;
    }
}

internal sealed class ConnectionResponse(byte result, byte version, byte platformId, byte fragmentId, ulong targetConstantId, uint targetVariableId, ReadOnlyMemory<byte> identifier, uint sessionId, byte playerCount, byte participantCount, byte playerInfoCount, IReadOnlyList<StationPlayerInfo> playerInfo, uint ackId) : IPiaPayload
{
    public const byte PacketType = 2;

    public byte Result { get; } = result;
    public byte Version { get; } = version;
    public byte PlatformId { get; } = platformId;
    public byte FragmentId { get; } = fragmentId;
    public ulong TargetConstantId { get; } = targetConstantId;
    public uint TargetVariableId { get; } = targetVariableId;
    public ReadOnlyMemory<byte> Identifier { get; } = identifier;
    public uint SessionId { get; } = sessionId;
    public byte PlayerCount { get; } = playerCount;
    public byte ParticipantCount { get; } = participantCount;
    public byte PlayerInfoCount { get; } = playerInfoCount;
    public IReadOnlyList<StationPlayerInfo> PlayerInfo { get; } = playerInfo;
    public uint AckId { get; } = ackId;

    public PiaProtocol Protocol => PiaProtocol.Station;

    public byte MessageFlags => 1;

    public static ConnectionResponse Parse(ReadOnlyMemory<byte> data)
    {
        var span = data.Span;
        var playerInfoSize = data.Length - 60;
        var reader = new BinarySpanReader(span);
        reader.ReadByte();
        var result = reader.ReadByte();
        var version = reader.ReadByte();
        var platformId = reader.ReadByte();
        var fragmentId = reader.ReadByte();
        var targetConstantId = reader.ReadUInt64BigEndian();
        var targetVariableId = reader.ReadUInt32BigEndian();
        var identifier = reader.ReadSpanAndAdvance(32).ToArray();
        var sessionId = reader.ReadUInt32BigEndian();
        var playerCount = reader.ReadByte();
        var participantCount = reader.ReadByte();
        var playerInfoCount = reader.ReadByte();
        var playerInfoBytes = reader.ReadSpanAndAdvance(playerInfoSize).ToArray();
        var ackId = reader.ReadUInt32BigEndian();
        var players = new List<StationPlayerInfo>(4);
        for (var index = 0; index < 4; index++)
        {
            players.Add(StationPlayerInfo.Parse(playerInfoBytes.AsMemory(index * 195, 195)));
        }

        return new ConnectionResponse(result, version, platformId, fragmentId, targetConstantId, targetVariableId, identifier, sessionId, playerCount, participantCount, playerInfoCount, players, ackId);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WriteByte(Result);
        writer.WriteByte(Version);
        writer.WriteByte(PlatformId);
        writer.WriteByte(FragmentId);
        writer.WriteUInt64BigEndian(TargetConstantId);
        writer.WriteUInt32BigEndian(TargetVariableId);
        writer.WriteMemory(Identifier);
        writer.WritePadding(Math.Max(0, 32 - Identifier.Length));
        writer.WriteUInt32BigEndian(SessionId);
        writer.WriteByte(PlayerCount);
        writer.WriteByte(ParticipantCount);
        writer.WriteByte(PlayerInfoCount);
        foreach (var info in PlayerInfo.Take(4))
        {
            writer.WriteMemory(info.ToArray());
        }

        var remaining = 4 - Math.Min(4, PlayerInfo.Count);
        writer.WritePadding(remaining * 195);
        writer.WriteUInt32BigEndian(AckId);
        return writer.ToArray();
    }
}

internal sealed class Ack(uint ackId) : IPiaPayload
{
    public const byte PacketType = 5;

    public uint AckId { get; } = ackId;

    public PiaProtocol Protocol => PiaProtocol.Station;

    public byte MessageFlags => 1;

    public static Ack Parse(ReadOnlyMemory<byte> data)
    {
        return new Ack(BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(4, 4)));
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WritePadding(3);
        writer.WriteUInt32BigEndian(AckId);
        return writer.ToArray();
    }
}
