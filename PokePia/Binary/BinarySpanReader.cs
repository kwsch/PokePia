using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace PokePia.Binary;

internal ref struct BinarySpanReader(ReadOnlySpan<byte> span)
{
    private readonly ReadOnlySpan<byte> _span = span;
    private int _position;

    public int Remaining => _span.Length - _position;

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        EnsureRemaining(count);
        _position += count;
    }

    public byte ReadByte()
    {
        EnsureRemaining(1);
        return _span[_position++];
    }

    public bool ReadBoolean() => ReadByte() != 0;

    public ushort ReadUInt16BigEndian()
    {
        var value = BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(sizeof(ushort)));
        _position += sizeof(ushort);
        return value;
    }

    public ushort ReadUInt16LittleEndian()
    {
        var value = BinaryPrimitives.ReadUInt16LittleEndian(ReadSpan(sizeof(ushort)));
        _position += sizeof(ushort);
        return value;
    }

    public short ReadInt16BigEndian()
    {
        var value = BinaryPrimitives.ReadInt16BigEndian(ReadSpan(sizeof(short)));
        _position += sizeof(short);
        return value;
    }

    public uint ReadUInt32BigEndian()
    {
        var value = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(sizeof(uint)));
        _position += sizeof(uint);
        return value;
    }

    public uint ReadUInt32LittleEndian()
    {
        var value = BinaryPrimitives.ReadUInt32LittleEndian(ReadSpan(sizeof(uint)));
        _position += sizeof(uint);
        return value;
    }

    public int ReadInt32LittleEndian()
    {
        var value = BinaryPrimitives.ReadInt32LittleEndian(ReadSpan(sizeof(int)));
        _position += sizeof(int);
        return value;
    }

    public ulong ReadUInt64BigEndian()
    {
        var value = BinaryPrimitives.ReadUInt64BigEndian(ReadSpan(sizeof(ulong)));
        _position += sizeof(ulong);
        return value;
    }

    public ReadOnlySpan<byte> ReadSpan(int count)
    {
        EnsureRemaining(count);
        return _span.Slice(_position, count);
    }

    public ReadOnlyMemory<byte> ReadMemory(int count)
    {
        EnsureRemaining(count);
        var memory = _span.Slice(_position, count).ToArray();
        _position += count;
        return memory;
    }

    public ReadOnlySpan<byte> ReadSpanAndAdvance(int count)
    {
        var result = ReadSpan(count);
        _position += count;
        return result;
    }

    public string ReadFixedString(int length, Encoding encoding)
    {
        var value = encoding.GetString(ReadSpanAndAdvance(length));
        var terminatorIndex = value.IndexOf('\0');
        return terminatorIndex >= 0 ? value[..terminatorIndex] : value;
    }

    public void Align4()
    {
        _position = (_position + 3) & ~3;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EnsureRemaining(int count)
    {
        if ((uint)(_position + count) > (uint)_span.Length)
        {
            throw new InvalidOperationException($"Cannot read {count} byte(s) from position {_position} in {_span.Length}-byte payload.");
        }
    }
}
