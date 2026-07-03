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

internal sealed class BrowseRequest(SessionSearchCriteria searchCriteria, CryptoChallenge cryptoChallenge) : IByteSerializable
{
    public const byte PacketType = 0;

    public SessionSearchCriteria SearchCriteria { get; } = searchCriteria ?? throw new ArgumentNullException(nameof(searchCriteria));

    public CryptoChallenge CryptoChallenge { get; } = cryptoChallenge ?? throw new ArgumentNullException(nameof(cryptoChallenge));

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
    public SessionInfo(uint gameMode, uint sessionId, IReadOnlyList<uint> attributes, ushort numberOfPlayers, ushort minimumPlayers, ushort maximumPlayers, byte systemCommunicationVersion, byte applicationCommunicationVersion, ushort sessionType, ReadOnlyMemory<byte> appData, bool isOpened, IPEndPoint hostAddress, ulong hostConstantId, uint hostVariableId, uint hostServiceVariableId, IReadOnlyList<LanPlayerInfo> playerInfo, ReadOnlyMemory<byte> sessionKeyParameter)
    {
        GameMode = gameMode;
        SessionId = sessionId;
        Attributes = attributes;
        NumberOfPlayers = numberOfPlayers;
        MinimumPlayers = minimumPlayers;
        MaximumPlayers = maximumPlayers;
        SystemCommunicationVersion = systemCommunicationVersion;
        ApplicationCommunicationVersion = applicationCommunicationVersion;
        SessionType = sessionType;
        AppData = appData;
        IsOpened = isOpened;
        HostAddress = hostAddress;
        HostConstantId = hostConstantId;
        HostVariableId = hostVariableId;
        HostServiceVariableId = hostServiceVariableId;
        PlayerInfo = playerInfo;
        SessionKeyParameter = sessionKeyParameter;
    }

    public uint GameMode { get; }
    public uint SessionId { get; }
    public IReadOnlyList<uint> Attributes { get; }
    public ushort NumberOfPlayers { get; }
    public ushort MinimumPlayers { get; }
    public ushort MaximumPlayers { get; }
    public byte SystemCommunicationVersion { get; }
    public byte ApplicationCommunicationVersion { get; }
    public ushort SessionType { get; }
    public ReadOnlyMemory<byte> AppData { get; }
    public bool IsOpened { get; }
    public IPEndPoint HostAddress { get; }
    public ulong HostConstantId { get; }
    public uint HostVariableId { get; }
    public uint HostServiceVariableId { get; }
    public IReadOnlyList<LanPlayerInfo> PlayerInfo { get; }
    public ReadOnlyMemory<byte> SessionKeyParameter { get; }

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
        return new SessionInfo(gameMode, sessionId, attributes, numberOfPlayers, minimumPlayers, maximumPlayers, systemCommunicationVersion, applicationCommunicationVersion, sessionType, appData, isOpened, new IPEndPoint(hostIp, hostPort), hostConstantId, hostVariableId, hostServiceVariableId, players, sessionKeyParameter);
    }
}

internal sealed class BrowseReply(SessionInfo sessionInfo, CryptoChallenge cryptoChallengeReply)
{
    public const byte PacketType = 1;

    public SessionInfo SessionInfo { get; } = sessionInfo ?? throw new ArgumentNullException(nameof(sessionInfo));

    public CryptoChallenge CryptoChallengeReply { get; } = cryptoChallengeReply ?? throw new ArgumentNullException(nameof(cryptoChallengeReply));

    public ReadOnlyMemory<byte> SessionKey
    {
        get
        {
            var keyParameter = SessionInfo.SessionKeyParameter.ToArray();
            keyParameter[^1]++;
            return HMACSHA256.HashData(LanProtocol.GameKey, keyParameter)[..16];
        }
    }

    public static BrowseReply Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new BinarySpanReader(data.Span);
        var packetType = reader.ReadByte();
        var size = reader.ReadUInt32BigEndian();
        if (packetType != PacketType || size != 0x511)
        {
            throw new InvalidOperationException("Unexpected browse reply header.");
        }

        return new BrowseReply(SessionInfo.Parse(reader.ReadSpanAndAdvance(1297).ToArray()), CryptoChallenge.Parse(reader.ReadSpanAndAdvance(58).ToArray()));
    }
}

internal sealed class HostRequest(uint sessionId) : IPiaPayload
{
    public const byte PacketType = 3;

    public uint SessionId { get; } = sessionId;
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

    public StationLocation StationLocation { get; } = stationLocation ?? throw new ArgumentNullException(nameof(stationLocation));

    public static HostMessage Parse(ReadOnlyMemory<byte> data)
    {
        var sessionId = BinaryPrimitives.ReadUInt32BigEndian(data.Span.Slice(12, 4));
        return new HostMessage(sessionId, StationLocation.Parse(data[16..]));
    }
}
