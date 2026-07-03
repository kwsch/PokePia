using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using PokePia.Binary;

namespace PokePia.Protocol;

internal sealed class PiaPacket : IByteSerializable
{
    public static ReadOnlySpan<byte> Magic => [0x32, 0xAB, 0x98, 0x64];

    public required bool IsEncrypted { get; init; }
    public required byte Version { get; init; }
    public required byte ConnectionId { get; init; }
    public required ushort PacketId { get; init; }

    public required ReadOnlyMemory<byte> Nonce
    {
        get;
        init
        {
            if (value.Length != 8)
                throw new ArgumentException("PIA nonce must be 8 bytes.", nameof(value));
            field = value;
        }
    }

    public required ReadOnlyMemory<byte> AuthTag
    {
        get;
        init
        {
            if (value.Length != 16)
                throw new ArgumentException("PIA auth tag must be 16 bytes.", nameof(value));
            field = value;
        }
    }

    public required ReadOnlyMemory<byte> Data { get; init; }

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
        return new PiaPacket
        {
            IsEncrypted = (flags & 0x80) != 0,
            Version = version,
            ConnectionId = connectionId,
            PacketId = packetId,
            Nonce = data.Slice(8, 8),
            AuthTag = data.Slice(16, 16),
            Data = data[32..],
        };
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

        return new PiaPacket
        {
            IsEncrypted = true,
            Version = 4,
            ConnectionId = connectionId,
            PacketId = packetId,
            Nonce = headerNonce[..8].ToArray(),
            AuthTag = authTag,
            Data = encrypted,
        };
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
    public required byte Flags { get; init; }
    public required byte MessageFlags { get; init; }
    public required ushort PayloadSize { get; init; }
    public required PiaProtocol ProtocolType { get; init; }
    public required int ProtocolPort { get; init; }
    public required ulong Destination { get; init; }
    public required ulong Source { get; init; }
    public required ReadOnlyMemory<byte> Payload { get; init; }

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
            messages.Add(new PiaMessage
            {
                Flags = flags,
                MessageFlags = messageFlags,
                PayloadSize = payloadSize,
                ProtocolType = protocolType,
                ProtocolPort = protocolPort,
                Destination = destination,
                Source = source,
                Payload = payload,
            });
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
        return new PiaMessage
        {
            Flags = 127,
            MessageFlags = payload.MessageFlags,
            PayloadSize = checked((ushort)bytes.Length),
            ProtocolType = payload.Protocol,
            ProtocolPort = protocolPort,
            Destination = destination,
            Source = source,
            Payload = bytes,
        };
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
