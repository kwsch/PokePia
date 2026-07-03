using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using PokePia.Binary;

namespace PokePia.Protocol;

internal enum PiaProtocol : byte
{
    KeepAlive = 0x08,
    Station = 0x14,
    Mesh = 0x18,
    SyncClock = 0x1C,
    Local = 0x24,
    Direct = 0x28,
    Net = 0x2C,
    Nat = 0x34,
    Lan = 0x44,
    BandwidthCheck = 0x54,
    Rtt = 0x58,
    Sync = 0x64,
    SyncEvent = 0x65,
    Unreliable = 0x68,
    RoundRobinUnreliable = 0x6C,
    Clone = 0x73,
    CloneAtomic = 0x74,
    CloneEvent = 0x75,
    CloneClock = 0x77,
    Voice = 0x78,
    Reliable = 0x7C,
    BroadcastReliable = 0x80,
    ReliableBroadcast = 0x84,
    Session = 0x94,
    Lobby = 0x98,
    Feedback = 0xA4,
    RelayService = 0xA8,
    WanNat = 0xAC,
}

internal sealed class PiaPacket : IByteSerializable
{
    private static readonly byte[] Magic = [0x32, 0xAB, 0x98, 0x64];

    public PiaPacket(bool isEncrypted, byte version, byte connectionId, ushort packetId, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> authTag, ReadOnlyMemory<byte> data)
    {
        if (nonce.Length != 8)
            throw new ArgumentException("PIA nonce must be 8 bytes.", nameof(nonce));

        if (authTag.Length != 16)
            throw new ArgumentException("PIA auth tag must be 16 bytes.", nameof(authTag));

        IsEncrypted = isEncrypted;
        Version = version;
        ConnectionId = connectionId;
        PacketId = packetId;
        Nonce = nonce;
        AuthTag = authTag;
        Data = data;
    }

    public bool IsEncrypted { get; }

    public byte Version { get; }

    public byte ConnectionId { get; }

    public ushort PacketId { get; }

    public ReadOnlyMemory<byte> Nonce { get; }

    public ReadOnlyMemory<byte> AuthTag { get; }

    public ReadOnlyMemory<byte> Data { get; }

    public static PiaPacket Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length < 32)
            throw new InvalidOperationException("PIA packet payload is too small.");

        var span = data.Span;
        if (!span[..4].SequenceEqual(Magic))
            throw new InvalidOperationException("PIA packet magic did not match.");

        var flags = span[4];
        var version = (byte)(flags & 0x7F);
        if (version != 4)
            throw new InvalidOperationException($"Unsupported PIA version {version}.");

        var connectionId = span[5];
        var packetId = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(6, 2));
        return new PiaPacket(
            isEncrypted: (flags & 0x80) != 0,
            version,
            connectionId,
            packetId,
            data.Slice(8, 8),
            data.Slice(16, 16),
            data[32..]);
    }

    public static PiaPacket FromMessage(PiaMessage message, byte connectionId, ushort packetId, ReadOnlySpan<byte> headerNonce, IPAddress sourceAddress, ReadOnlySpan<byte> sessionKey)
    {
        if (headerNonce.Length != 12)
            throw new ArgumentException("Header nonce must be 12 bytes.", nameof(headerNonce));

        if (sourceAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 source addresses are supported.", nameof(sourceAddress));

        if (sessionKey.Length != 16)
            throw new ArgumentException("Session key must be 16 bytes.", nameof(sessionKey));

        var nonce = BuildNonce(sourceAddress, connectionId, headerNonce[5..12]);
        var messageBytes = PadToBlock(message.ToArray());
        var encrypted = new byte[messageBytes.Length];
        var authTag = new byte[16];

        using var aes = new AesGcm(sessionKey, 16);
        aes.Encrypt(nonce, messageBytes, encrypted, authTag);

        return new PiaPacket(true, 4, connectionId, packetId, headerNonce[..8].ToArray(), authTag, encrypted);
    }

    public IReadOnlyList<PiaMessage> DecryptMessages(IPAddress sourceAddress, ReadOnlySpan<byte> sessionKey)
    {
        if (!IsEncrypted)
            return PiaMessage.ParseMany(Data);

        if (sessionKey.Length != 16)
            throw new ArgumentException("Session key must be 16 bytes.", nameof(sessionKey));

        var nonce = BuildNonce(sourceAddress, ConnectionId, Nonce.Span[1..8]);
        var plaintext = new byte[Data.Length];

        using var aes = new AesGcm(sessionKey, 16);
        aes.Decrypt(nonce, Data.Span, AuthTag.Span, plaintext);
        return PiaMessage.ParseMany(plaintext);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.Write(Magic);
        writer.WriteByte((byte)(Version | (IsEncrypted ? 0x80 : 0)));
        writer.WriteByte(ConnectionId);
        writer.WriteUInt16BigEndian(PacketId);
        writer.WriteMemory(Nonce);
        writer.WriteMemory(AuthTag);
        writer.WriteMemory(Data);
        return writer.ToArray();
    }

    private static byte[] BuildNonce(IPAddress address, byte connectionId, ReadOnlySpan<byte> suffix)
    {
        var addressBytes = address.GetAddressBytes();
        if (addressBytes.Length != 4)
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));

        if (suffix.Length != 7)
            throw new ArgumentException("PIA nonce suffix must be 7 bytes.", nameof(suffix));

        var nonce = new byte[12];
        addressBytes.CopyTo(nonce, 0);
        nonce[4] = connectionId;
        suffix.CopyTo(nonce.AsSpan(5));
        return nonce;
    }

    private static byte[] PadToBlock(byte[] data)
    {
        var padding = (16 - (data.Length & 15)) & 15;
        if (padding == 0)
            return data;

        Array.Resize(ref data, data.Length + padding);
        data.AsSpan(data.Length - padding).Fill(0xFF);
        return data;
    }
}

internal sealed class PiaMessage : IByteSerializable
{
    public PiaMessage(byte flags, byte messageFlags, ushort payloadSize, PiaProtocol protocolType, int protocolPort, ulong destination, ulong source, ReadOnlyMemory<byte> payload)
    {
        Flags = flags;
        MessageFlags = messageFlags;
        PayloadSize = payloadSize;
        ProtocolType = protocolType;
        ProtocolPort = protocolPort;
        Destination = destination;
        Source = source;
        Payload = payload;
    }

    public byte Flags { get; }

    public byte MessageFlags { get; }

    public ushort PayloadSize { get; }

    public PiaProtocol ProtocolType { get; }

    public int ProtocolPort { get; }

    public ulong Destination { get; }

    public ulong Source { get; }

    public ReadOnlyMemory<byte> Payload { get; }

    public static IReadOnlyList<PiaMessage> ParseMany(ReadOnlyMemory<byte> data)
    {
        var span = data.Span;
        var messages = new List<PiaMessage>();
        byte messageFlags = 0;
        ushort payloadSize = 0;
        PiaProtocol protocolType = 0;
        var protocolPort = 0;
        ulong destination = 0;
        ulong source = 0;
        var pointer = 0;

        while (pointer < span.Length)
        {
            var flags = span[pointer++];
            if (flags == 0xFF)
                break;

            if ((flags & 1) != 0)
            {
                EnsureRemaining(span, pointer, 1);
                messageFlags = span[pointer++];
            }

            if ((flags & 2) != 0)
            {
                EnsureRemaining(span, pointer, 2);
                payloadSize = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pointer, 2));
                pointer += 2;
            }

            if ((flags & 4) != 0)
            {
                EnsureRemaining(span, pointer, 4);
                protocolType = (PiaProtocol)span[pointer++];
                var portBytes = span.Slice(pointer, 3);
                pointer += 3;
                protocolPort = (portBytes[0] << 16) | (portBytes[1] << 8) | portBytes[2];
            }

            if ((flags & 8) != 0)
            {
                EnsureRemaining(span, pointer, 8);
                destination = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(pointer, 8));
                pointer += 8;
            }

            if ((flags & 16) != 0)
            {
                EnsureRemaining(span, pointer, 8);
                source = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(pointer, 8));
                pointer += 8;
            }

            EnsureRemaining(span, pointer, payloadSize);
            var payload = span.Slice(pointer, payloadSize).ToArray();
            pointer += payloadSize;

            // Python reference behavior:
            // ptr += payload_size
            // ptr += 3
            // ptr &= 0xFFFFFFFC
            // This is equivalent to: ptr = (ptr + 3) & ~3
            pointer = (pointer + 3) & ~3;
            messages.Add(new PiaMessage(flags, messageFlags, payloadSize, protocolType, protocolPort, destination, source, payload));
        }

        return messages;
    }

    private static void EnsureRemaining(ReadOnlySpan<byte> data, int pointer, int count)
    {
        if ((uint)(pointer + count) > (uint)data.Length)
            throw new InvalidOperationException($"Cannot read {count} byte(s) from position {pointer} in {data.Length}-byte payload.");
    }

    public static PiaMessage FromPayload(IPiaPayload payload, int protocolPort = 0, ulong destination = 0, ulong source = 0)
    {
        var bytes = payload.ToArray();
        return new PiaMessage(127, payload.MessageFlags, checked((ushort)bytes.Length), payload.Protocol, protocolPort, destination, source, bytes);
    }

    public byte[] ToArray()
    {
        var writer = new BinarySpanWriter();
        writer.WriteByte(Flags);
        if ((Flags & 1) != 0)
            writer.WriteByte(MessageFlags);

        if ((Flags & 2) != 0)
            writer.WriteUInt16BigEndian(PayloadSize);

        if ((Flags & 4) != 0)
        {
            writer.WriteByte((byte)ProtocolType);
            writer.Write([(byte)(ProtocolPort >> 16), (byte)(ProtocolPort >> 8), (byte)ProtocolPort]);
        }

        if ((Flags & 8) != 0)
            writer.WriteUInt64BigEndian(Destination);

        if ((Flags & 16) != 0)
            writer.WriteUInt64BigEndian(Source);

        writer.WriteMemory(Payload);
        return writer.ToArray();
    }
}
