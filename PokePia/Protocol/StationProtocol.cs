using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using PokePia.Binary;

namespace PokePia.Protocol;

internal sealed class StationLocation : IByteSerializable
{
    public required byte PublicAddressSize { get; init; }
    public required byte PrivateAddressSize { get; init; }
    public required IPEndPoint PublicAddress { get; init; }
    public required IPEndPoint PrivateAddress { get; init; }
    public required IPEndPoint RelayAddress { get; init; }
    public required ulong ConstantId { get; init; }
    public required uint VariableId { get; init; }
    public required uint ServiceVariableId { get; init; }
    public required byte Flags { get; init; }
    public required byte NatLocation { get; init; }
    public required byte ProbeInit { get; init; }
    public required bool IsPrivateAddressAvailable { get; init; }

    public static StationLocation FromAddress(IPEndPoint address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 station addresses are supported.", nameof(address));

        var addressBytes = address.Address.GetAddressBytes();
        var ipValue = BinaryPrimitives.ReadUInt32BigEndian(addressBytes);
        var variableIdBytes = RandomNumberGenerator.GetBytes(sizeof(uint));
        return new StationLocation
        {
            PublicAddressSize = 2,
            PrivateAddressSize = 6,
            PublicAddress = new IPEndPoint(IPAddress.Any, 0),
            PrivateAddress = address,
            RelayAddress = new IPEndPoint(IPAddress.Any, 0),
            ConstantId = ((ulong)ipValue << 32) | (uint)address.Port,
            VariableId = BinaryPrimitives.ReadUInt32LittleEndian(variableIdBytes),
            ServiceVariableId = ((ipValue & 0xFFFFu) << 16) | (uint)address.Port,
            Flags = 0,
            NatLocation = 0,
            ProbeInit = 0,
            IsPrivateAddressAvailable = true,
        };
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

        var publicAddress = publicAddressSize > 2
            ? new IPEndPoint(new IPAddress(publicIpBytes), publicPort)
            : new IPEndPoint(IPAddress.Any, publicPort);

        return new StationLocation
        {
            PublicAddressSize = publicAddressSize,
            PrivateAddressSize = privateAddressSize,
            PublicAddress = publicAddress,
            PrivateAddress = new IPEndPoint(privateIp, privatePort),
            RelayAddress = new IPEndPoint(relayIp, relayPort),

            ConstantId = constantId,
            VariableId = variableId,
            ServiceVariableId = serviceVariableId,
            Flags = flags,
            NatLocation = natLocation,
            ProbeInit = probeInit,
            IsPrivateAddressAvailable = isPrivateAddressAvailable,
        };
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

internal sealed class ConnectionRequest : IPiaPayload
{
    public const byte PacketType = 1;

    public required byte ConnectionId { get; init; }
    public required byte Version { get; init; }
    public required bool IsInverseConnection { get; init; }
    public required ulong TargetConstantId { get; init; }
    public required uint TargetVariableId { get; init; }
    public required byte InverseConnectionId { get; init; }
    public required StationLocation StationLocation { get; init; }
    public required uint AckId { get; init; }
    public Ack Ack() => new() { AckId = AckId };

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
        var stationLocation = StationLocation.Parse(data[17..^4]);
        return new ConnectionRequest
        {
            ConnectionId = connectionId,
            Version = version,
            IsInverseConnection = isInverseConnection,
            TargetConstantId = targetConstantId,
            TargetVariableId = targetVariableId,
            InverseConnectionId = inverseConnectionId,
            StationLocation = stationLocation,
            AckId = ackId,
        };
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

internal sealed class StationPlayerInfo : IByteSerializable
{
    public required string PlayerName { get; init; }
    public required byte PlayerNameEncodingType { get; init; }
    public required string AccountName { get; init; }
    public required byte AccountNameEncodingType { get; init; }
    public required byte Language { get; init;  }
    public required ReadOnlyMemory<byte> PlayHistoryRegistrationKey { get; init; }
    public required ulong PrincipalId { get; init; }

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
        return new StationPlayerInfo
        {
            PlayerName = Decode(playerNameBytes, playerNameEncodingType),
            PlayerNameEncodingType = playerNameEncodingType,
            AccountName = Decode(accountNameBytes, accountNameEncodingType),
            AccountNameEncodingType = accountNameEncodingType,
            Language = language,
            PlayHistoryRegistrationKey = playHistoryRegistrationKey,
            PrincipalId = principalId,
        };
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
            throw new ArgumentException($"Encoded string exceeds field length {fieldLength}.", nameof(value));

        var buffer = new byte[fieldLength];
        bytes.CopyTo(buffer, 0);
        return buffer;
    }
}

internal sealed class ConnectionResponse : IPiaPayload
{
    public const byte PacketType = 2;

    public required byte Result { get; init; }
    public required byte Version { get; init; }
    public required byte PlatformId { get; init; }
    public required byte FragmentId { get; init; }
    public required ulong TargetConstantId { get; init; }
    public required uint TargetVariableId { get; init; }
    public required ReadOnlyMemory<byte> Identifier { get; init; }
    public required uint SessionId { get; init; }
    public required byte PlayerCount { get; init; }
    public required byte ParticipantCount { get; init; }
    public required byte PlayerInfoCount { get; init; }
    public required IReadOnlyList<StationPlayerInfo> PlayerInfo { get; init; }
    public required uint AckId { get; init; }
    public Ack Ack() => new() { AckId = AckId };

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

        return new ConnectionResponse
        {
            Result = result,
            Version = version,
            PlatformId = platformId,
            FragmentId = fragmentId,
            TargetConstantId = targetConstantId,
            TargetVariableId = targetVariableId,
            Identifier = identifier,
            SessionId = sessionId,
            PlayerCount = playerCount,
            ParticipantCount = participantCount,
            PlayerInfoCount = playerInfoCount,
            PlayerInfo = players,
            AckId = ackId,
        };
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

internal sealed class Ack : IPiaPayload
{
    public const byte PacketType = 5;

    public required uint AckId { get; init; }

    public PiaProtocol Protocol => PiaProtocol.Station;

    public byte MessageFlags => 1;

    public static Ack Parse(ReadOnlyMemory<byte> data)
    {
        return new Ack { AckId = BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(4, 4)) };
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
