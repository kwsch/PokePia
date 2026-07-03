using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PokePia.Binary;

internal sealed class BinarySpanWriter
{
    private readonly MemoryStream _stream = new();
    public int Length => checked((int)_stream.Length);

    public void WriteByte(byte value) => _stream.WriteByte(value);

    public void WriteBoolean(bool value) => WriteByte(value ? (byte)1 : (byte)0);

    public void WriteUInt16BigEndian(ushort value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        Write(buffer);
    }

    public void WriteUInt16LittleEndian(ushort value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        Write(buffer);
    }

    public void WriteInt16BigEndian(short value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(short)];
        BinaryPrimitives.WriteInt16BigEndian(buffer, value);
        Write(buffer);
    }

    public void WriteUInt32BigEndian(uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        Write(buffer);
    }

    public void WriteUInt32LittleEndian(uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        Write(buffer);
    }

    public void WriteUInt64BigEndian(ulong value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        Write(buffer);
    }

    public void Write(ReadOnlySpan<byte> span) => _stream.Write(span);

    public void WriteMemory(ReadOnlyMemory<byte> memory)
    {
        if (memory.IsEmpty)
            return;

        Write(memory.Span);
    }

    public void WriteFixedString(string value, int byteLength, Encoding encoding)
    {
        var bytes = encoding.GetBytes(value);
        if (bytes.Length > byteLength)
            throw new ArgumentException($"Encoded string length {bytes.Length} exceeds fixed field size {byteLength}.", nameof(value));

        Write(bytes);
        if (bytes.Length < byteLength)
            Write(new byte[byteLength - bytes.Length]);
    }

    public void WriteIPAddress(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4 || address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));

        Write(bytes);
    }

    public void WritePadding(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (count == 0)
            return;

        Write(new byte[count]);
    }

    public void Align4()
    {
        var pad = (4 - (Length & 3)) & 3;
        WritePadding(pad);
    }

    public byte[] ToArray() => _stream.ToArray();
}
