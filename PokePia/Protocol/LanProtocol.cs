using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using PokePia.Binary;

namespace PokePia.Protocol;

internal static class LanProtocol
{
    public static ReadOnlySpan<byte> GameKey => "p1frXqxmeCZWFv0X"u8;
}

internal sealed class CryptoChallenge : IByteSerializable
{
    public CryptoChallenge(byte version, bool cryptoEnabled, ulong counter, ReadOnlyMemory<byte> challengeKey, ReadOnlyMemory<byte> authTag, ReadOnlyMemory<byte> data)
    {
        if (challengeKey.Length != 16)
            throw new ArgumentException("Challenge key must be 16 bytes.", nameof(challengeKey));

        if (authTag.Length != 16)
            throw new ArgumentException("Challenge auth tag must be 16 bytes.", nameof(authTag));

        Version = version;
        CryptoEnabled = cryptoEnabled;
        Counter = counter;
        ChallengeKey = challengeKey;
        AuthTag = authTag;
        Data = data;
    }

    public byte Version { get; }
    public bool CryptoEnabled { get; }
    public ulong Counter { get; }
    public ReadOnlyMemory<byte> ChallengeKey { get; }
    public ReadOnlyMemory<byte> AuthTag { get; }
    public ReadOnlyMemory<byte> Data { get; }

    public static CryptoChallenge Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length is not (0x12A or 0x3A))
            throw new InvalidOperationException($"Unexpected crypto challenge size {data.Length}.");

        var reader = new BinarySpanReader(data.Span);
        var version = reader.ReadByte();
        var cryptoEnabled = reader.ReadBoolean();
        if (version != 2 || !cryptoEnabled)
            throw new InvalidOperationException("Unsupported LAN crypto challenge.");

        var counter = reader.ReadUInt64BigEndian();
        var challengeKey = reader.ReadSpanAndAdvance(16).ToArray();
        var authTag = reader.ReadSpanAndAdvance(16).ToArray();
        var payload = reader.ReadSpanAndAdvance(reader.Remaining).ToArray();
        return new CryptoChallenge(version, cryptoEnabled, counter, challengeKey, authTag, payload);
    }

    public static CryptoChallenge GenerateChallenge(ulong counter, IPAddress address)
    {
        var challengeKey = RandomNumberGenerator.GetBytes(16);
        var challengeData = RandomNumberGenerator.GetBytes(256);

        var ipBytes = address.GetAddressBytes();
        if (ipBytes.Length != 4)
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));

        var broadcastValue = BinaryPrimitives.ReadUInt32BigEndian(ipBytes) | 0xFFu;
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(nonce[..4], broadcastValue);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], counter);

        var encryptedKey = EncryptEcb(challengeKey, LanProtocol.GameKey);
        var encryptedChallenge = new byte[challengeData.Length];
        var authTag = new byte[16];
        using var aes = new AesGcm(encryptedKey, 16);
        aes.Encrypt(nonce, challengeData, encryptedChallenge, authTag);
        return new CryptoChallenge(2, true, counter, challengeKey, authTag, encryptedChallenge);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(Version);
        writer.WriteBoolean(CryptoEnabled);
        writer.WriteUInt64BigEndian(Counter);
        writer.WriteMemory(ChallengeKey);
        writer.WriteMemory(AuthTag);
        writer.WriteMemory(Data);
        return writer.ToArray();
    }

    private static byte[] EncryptEcb(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = [.. key];
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock([.. input], 0, input.Length);
    }
}

internal sealed class SessionSearchCriteria : IByteSerializable
{
    public const uint TradeGameMode = 60001;

    public SessionSearchCriteria(short minimumPlayers, short maximumPlayers, bool openedOnly, bool vacantOnly, uint resultRangeOffset, uint resultRangeSize, uint gameMode, uint sessionType, ReadOnlyMemory<byte> attributeData, uint searchFlags)
    {
        if (attributeData.Length > 540)
            throw new ArgumentException("LAN search criteria attribute data cannot exceed 540 bytes.", nameof(attributeData));

        MinimumPlayers = minimumPlayers;
        MaximumPlayers = maximumPlayers;
        OpenedOnly = openedOnly;
        VacantOnly = vacantOnly;
        ResultRangeOffset = resultRangeOffset;
        ResultRangeSize = resultRangeSize;
        GameMode = gameMode;
        SessionType = sessionType;
        AttributeData = attributeData;
        SearchFlags = searchFlags;
    }

    public short MinimumPlayers { get; }
    public short MaximumPlayers { get; }
    public bool OpenedOnly { get; }
    public bool VacantOnly { get; }
    public uint ResultRangeOffset { get; }
    public uint ResultRangeSize { get; }
    public uint GameMode { get; }
    public uint SessionType { get; }
    public ReadOnlyMemory<byte> AttributeData { get; }
    public uint SearchFlags { get; }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteInt16BigEndian(MinimumPlayers);
        writer.WriteInt16BigEndian(MinimumPlayers);
        writer.WriteInt16BigEndian(MaximumPlayers);
        writer.WriteInt16BigEndian(MaximumPlayers);
        writer.WriteBoolean(OpenedOnly);
        writer.WriteBoolean(VacantOnly);
        writer.WriteUInt32BigEndian(ResultRangeOffset);
        writer.WriteUInt32BigEndian(ResultRangeSize);
        writer.WriteUInt32BigEndian(GameMode);
        writer.WriteUInt32BigEndian(SessionType);
        writer.WriteMemory(AttributeData);
        writer.WritePadding(540 - AttributeData.Length);
        writer.WriteUInt32BigEndian(SearchFlags);
        return writer.ToArray();
    }
}

internal sealed class BrowseRequest : IByteSerializable
{
    public const byte PacketType = 0;

    public required SessionSearchCriteria SearchCriteria { get; init; }
    public required CryptoChallenge CryptoChallenge { get; init; }


    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WriteUInt32BigEndian(0x23A);
        writer.WriteMemory(SearchCriteria.ToArray());
        writer.WriteMemory(CryptoChallenge.ToArray());
        return writer.ToArray();
    }
}

internal sealed class LanPlayerInfo(byte role, byte encodingType, ReadOnlyMemory<byte> name, ulong stationId)
{
    public byte Role { get; } = role;
    public byte EncodingType { get; } = encodingType;
    public ReadOnlyMemory<byte> Name { get; } = name;
    public ulong StationId { get; } = stationId;
    public bool HasValue => Role != 0;

    public string DisplayName => EncodingType switch
    {
        1 => System.Text.Encoding.UTF8.GetString(Name.Span).TrimEnd('\0'),
        2 => System.Text.Encoding.Unicode.GetString(Name.Span).TrimEnd('\0'),
        _ => string.Empty,
    };

    public static LanPlayerInfo Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        return new LanPlayerInfo(reader.ReadByte(), reader.ReadByte(), reader.ReadSpanAndAdvance(40).ToArray(), reader.ReadUInt64BigEndian());
    }
}

internal sealed class SessionInfo
{
    public required uint GameMode { get; init; }
    public required uint SessionId { get; init; }
    public required IReadOnlyList<uint> Attributes { get; init; }
    public required ushort NumberOfPlayers { get; init; }
    public required ushort MinimumPlayers { get; init; }
    public required ushort MaximumPlayers { get; init; }
    public required byte SystemCommunicationVersion { get; init; }
    public required byte ApplicationCommunicationVersion { get; init; }
    public required ushort SessionType { get; init; }
    public required ReadOnlyMemory<byte> AppData { get; init; }
    public required bool IsOpened { get; init; }
    public required IPEndPoint HostAddress { get; init; }
    public required ulong HostConstantId { get; init; }
    public required uint HostVariableId { get; init; }
    public required uint HostServiceVariableId { get; init; }
    public required IReadOnlyList<LanPlayerInfo> PlayerInfo { get; init; }
    public required ReadOnlyMemory<byte> SessionKeyParameter { get; init; }

    public static SessionInfo Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        var gameMode = reader.ReadUInt32BigEndian();
        var sessionId = reader.ReadUInt32BigEndian();
        var attributes = new uint[6];
        for (var index = 0; index < attributes.Length; index++)
            attributes[index] = reader.ReadUInt32BigEndian();

        var numberOfPlayers = reader.ReadUInt16BigEndian();
        var minimumPlayers = reader.ReadUInt16BigEndian();
        var maximumPlayers = reader.ReadUInt16BigEndian();
        var systemCommunicationVersion = reader.ReadByte();
        var applicationCommunicationVersion = reader.ReadByte();
        var sessionType = reader.ReadUInt16BigEndian();
        var appData = reader.ReadSpanAndAdvance(384).ToArray();
        reader.Advance(4);
        var isOpened = reader.ReadBoolean();
        var hostIp = new IPAddress(reader.ReadSpanAndAdvance(4));
        reader.Advance(12);
        var hostPort = reader.ReadUInt16BigEndian();
        var hostConstantId = reader.ReadUInt64BigEndian();
        var hostVariableId = reader.ReadUInt32BigEndian();
        var hostServiceVariableId = reader.ReadUInt32BigEndian();
        var playerInfoBytes = reader.ReadSpanAndAdvance(800);
        var players = new List<LanPlayerInfo>(16);
        for (var index = 0; index < 16; index++)
            players.Add(LanPlayerInfo.Parse(playerInfoBytes.Slice(index * 50, 50).ToArray()));

        var sessionKeyParameter = reader.ReadSpanAndAdvance(32).ToArray();
        return new SessionInfo
        {
            GameMode = gameMode,
            SessionId = sessionId,
            Attributes = attributes,
            NumberOfPlayers = numberOfPlayers,
            MinimumPlayers = minimumPlayers,
            MaximumPlayers = maximumPlayers,
            SystemCommunicationVersion = systemCommunicationVersion,
            ApplicationCommunicationVersion = applicationCommunicationVersion,
            SessionType = sessionType,
            AppData = appData,
            IsOpened = isOpened,
            HostAddress = new IPEndPoint(hostIp, hostPort),
            HostConstantId = hostConstantId,
            HostVariableId = hostVariableId,
            HostServiceVariableId = hostServiceVariableId,
            PlayerInfo = players,
            SessionKeyParameter = sessionKeyParameter,
        };
    }
}

internal sealed class BrowseReply(SessionInfo sessionInfo, CryptoChallenge cryptoChallengeReply)
{
    public const byte PacketType = 1;

    public SessionInfo SessionInfo { get; } = sessionInfo;

    public CryptoChallenge CryptoChallengeReply { get; } = cryptoChallengeReply;

    public ReadOnlyMemory<byte> SessionKey
    {
        get
        {
            var keyParameter = SessionInfo.SessionKeyParameter.ToArray();
            keyParameter[^1]++;
            return HMACSHA256.HashData(LanProtocol.GameKey, keyParameter).AsMemory()[..16];
        }
    }

    public static BrowseReply Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        var packetType = reader.ReadByte();
        var size = reader.ReadUInt32BigEndian();
        if (packetType != PacketType || size != 0x511)
            throw new InvalidOperationException("Unexpected browse reply header.");

        var session = reader.ReadSpanAndAdvance(1297);
        var cryptoChallenge = reader.ReadSpanAndAdvance(58);
        return new BrowseReply(SessionInfo.Parse(session.ToArray()), CryptoChallenge.Parse(cryptoChallenge.ToArray()));
    }
}

internal sealed class HostRequest : IPiaPayload
{
    public const byte PacketType = 3;

    public required uint SessionId { get; init; }
    public PiaProtocol Protocol => PiaProtocol.Lan;
    public byte MessageFlags => 9;

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(PacketType);
        writer.WritePadding(11);
        writer.WriteUInt32BigEndian(SessionId);
        return writer.ToArray();
    }
}

internal sealed class HostMessage(uint sessionId, StationLocation stationLocation)
{
    public const byte PacketType = 4;

    public uint SessionId { get; } = sessionId;

    public StationLocation StationLocation { get; } = stationLocation;

    public static HostMessage Parse(ReadOnlyMemory<byte> data)
    {
        var sessionId = BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(12, 4));
        return new HostMessage(sessionId, StationLocation.Parse(data[16..]));
    }
}
