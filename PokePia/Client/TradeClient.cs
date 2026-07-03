using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using PokePia.Protocol;
using PokePia.Trade;

namespace PokePia.Client;

internal sealed class TradeClient : IDisposable
{
    private readonly Socket _socket;
    private readonly List<Socket> _listenerSockets;
    private readonly List<Task> _listenerTasks;
    private readonly CancellationTokenSource _listenerCancellation = new();
    private readonly object _queueLock = new();
    private readonly List<Packet> _packetQueue = [];
    private readonly SaveContext _saveContext = new();

    private uint _ackCounter;
    private ushort _packetIdCounter;

    private byte _connectionId;
    private SessionInfo? _sessionInfo;
    private StationLocation? _hostStationLocation;
    private byte[] _sessionKey = [];

    public TradeClient(Action<string>? logger = null)
    {
        Log = logger ?? Console.WriteLine;
        var localIp = ResolveLocalIpAddress();
        StationLocation = StationLocation.FromAddress(new IPEndPoint(localIp, 49152));

        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);

        _listenerSockets = [_socket, CreateListenerSocket(40000)];
        _listenerTasks =
        [
            Task.Run(() => ListenOnSocket(_socket, StationLocation.PrivateAddress.Port, _listenerCancellation.Token), _listenerCancellation.Token),
            Task.Run(() => ListenOnSocket(_listenerSockets[1], 40000, _listenerCancellation.Token), _listenerCancellation.Token),
        ];
    }

    public StationLocation StationLocation { get; }

    private Action<string> Log { get; }

    /// <summary>
    /// Broadcasts LAN search traffic and discovers host session metadata.
    /// </summary>
    public void Matchmake()
    {
        ClearPacketQueue();

        ulong challengeCounter = 1;
        Packet? reply;
        do
        {
            Log("Broadcasting BrowseRequest");
            ClearPacketQueue();
            var request = new BrowseRequest(
                new SessionSearchCriteria(
                    minimumPlayers: -1,
                    maximumPlayers: 2,
                    openedOnly: true,
                    vacantOnly: true,
                    resultRangeOffset: 0,
                    resultRangeSize: 8,
                    gameMode: SessionSearchCriteria.TradeGameMode,
                    sessionType: 0,
                    attributeData: ReadOnlyMemory<byte>.Empty,
                    searchFlags: 0x10 | 0x2),
                CryptoChallenge.GenerateChallenge(challengeCounter, StationLocation.PrivateAddress.Address));

            BroadcastPacket(request, 30000);
            challengeCounter++;
            reply = WaitForPacket(packet => packet is { IsPia: false, PacketType: BrowseReply.PacketType }, TimeSpan.FromSeconds(5));
            if (reply is null)
                Log("No BrowseReply found after 5 seconds...");
        }
        while (reply is null);

        var browseReply = BrowseReply.Parse(reply.Data);
        _sessionInfo = browseReply.SessionInfo;
        _sessionKey = browseReply.SessionKey.ToArray();

        Log($"BrowseReply session id: {_sessionInfo.SessionId} received from {_sessionInfo.HostAddress.Address}:{_sessionInfo.HostAddress.Port}");

        Packet? hostReply;
        do
        {
            Log("Sending HostRequest");
            ClearPacketQueue();
            SendPiaPayload(new HostRequest(_sessionInfo.SessionId));
            hostReply = WaitForPacket(packet => packet is { IsPia: true, PacketType: HostMessage.PacketType }, TimeSpan.FromSeconds(5));
            if (hostReply is null)
                Log("No HostMessage found after 5 seconds...");
        }
        while (hostReply is null);

        var hostMessage = HostMessage.Parse(hostReply.PiaMessage!.Payload);
        _hostStationLocation = hostMessage.StationLocation;
        Log("HostMessage received");
    }

    /// <summary>
    /// Performs Station connection handshake with the discovered host.
    /// </summary>
    public void EstablishConnection()
    {
        EnsureTradeReady();
        ClearPacketQueue();

        _connectionId = GenerateConnectionId();
        var ack = GenerateAcknowledgementId();
        Packet? inverseRequestPacket;

        while (true)
        {
            Log("Sending ConnectionRequest");
            ClearPacketQueue();
            SendPiaPayload(new ConnectionRequest(_connectionId, 9, false, _hostStationLocation!.ConstantId, _hostStationLocation.VariableId, 0, StationLocation, ack));

            if (WaitForAck(ack, TimeSpan.FromSeconds(5)))
            {
                inverseRequestPacket = WaitForPacket(packet => packet is { IsPia: true, PacketType: ConnectionRequest.PacketType }, TimeSpan.FromSeconds(5));
                if (inverseRequestPacket is not null)
                    break;

                Log("No inverse request found after 5 seconds...");
            }
            else
            {
                Log("No acknowledgement found after 5 seconds...");
            }
        }

        var inverseRequest = ConnectionRequest.Parse(inverseRequestPacket.PiaMessage!.Payload);
        Log($"Inverse request received connection id: {inverseRequest.ConnectionId}");
        SendPiaPayload(new Ack(inverseRequest.AckId));

        Packet? responsePacket;
        while (true)
        {
            Log("Sending ConnectionResponse");
            ClearPacketQueue();
            ack = GenerateAcknowledgementId();

            SendPiaPayload(
                new ConnectionResponse(
                    result: 0,
                    version: 9,
                    platformId: 4,
                    fragmentId: 0,
                    targetConstantId: _hostStationLocation.ConstantId,
                    targetVariableId: _hostStationLocation.VariableId,
                    identifier: Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000000"),
                    sessionId: _sessionInfo!.SessionId,
                    playerCount: 1,
                    participantCount: 1,
                    playerInfoCount: 1,
                    playerInfo:
                    [
                        new StationPlayerInfo(
                            playerName: " ",
                            playerNameEncodingType: 1,
                            accountName: " ",
                            accountNameEncodingType: 1,
                            language: 0,
                            playHistoryRegistrationKey: ReadOnlyMemory<byte>.Empty,
                            principalId: 0),
                    ],
                    ackId: ack));

            if (WaitForAck(ack, TimeSpan.FromSeconds(5)))
            {
                responsePacket = WaitForPacket(packet => packet is { IsPia: true, PacketType: ConnectionResponse.PacketType }, TimeSpan.FromSeconds(5));
                if (responsePacket is not null)
                    break;

                Log("No ConnectionResponse found after 5 seconds...");
            }
            else
            {
                Log("No acknowledgement found after 5 seconds...");
            }
        }

        var response = ConnectionResponse.Parse(responsePacket.PiaMessage!.Payload);
        Log("ConnectionResponse received");
        Log("Players connected:");
        for (var index = 0; index < response.PlayerInfoCount; index++)
        {
            Log($"  Player {index + 1}: {response.PlayerInfo[index].AccountName}");
        }

        SendPiaPayload(new Ack(response.AckId));
    }

    /// <summary>
    /// Performs mesh join handshake on the established station connection.
    /// </summary>
    public void JoinMesh()
    {
        EnsureTradeReady();
        ClearPacketQueue();

        Packet? responsePacket;
        while (true)
        {
            Log("Sending JoinRequest");
            ClearPacketQueue();
            var ack = GenerateAcknowledgementId();
            SendPiaPayload(new JoinRequest(ack));

            if (WaitForAck(ack, TimeSpan.FromSeconds(5)))
            {
                responsePacket = WaitForPacket(packet => packet is { IsPia: true, PacketType: JoinResponse.PacketType }, TimeSpan.FromSeconds(5));
                if (responsePacket is not null)
                    break;

                Log("No JoinResponse found after 5 seconds...");
            }
            else
            {
                Log("No acknowledgement found after 5 seconds...");
            }
        }

        var response = JoinResponse.Parse(responsePacket.PiaMessage!.Payload);
        Log("JoinResponse received");
        SendPiaPayload(new Ack(response.AckId));
    }

    /// <summary>
    /// Sends required reliable commands and captures the first 3-fragment trade broadcast snapshot.
    /// </summary>
    public TradeSnapshot InitiateTrade()
    {
        EnsureTradeReady();
        ClearPacketQueue();

        SendPiaPayload(SlidingWindowMessage.FromPayload(Convert.FromHexString("610000001200"), 15, 1), source: StationLocation.ConstantId);
        SendPiaPayload(SlidingWindowMessage.FromPayload(Convert.FromHexString("610000000a00"), 7, 2), source: StationLocation.ConstantId);
        SendPiaPayload(SlidingWindowMessage.FromPayload(Convert.FromHexString("610000001a00"), 7, 3), source: StationLocation.ConstantId);
        SendPiaPayload(SlidingWindowMessage.FromPayload(Convert.FromHexString("60ea00000a00"), 7, 4), source: StationLocation.ConstantId);

        BroadcastPiaPayload(
            BroadcastSlidingWindowMessage.FromPayload(
                Convert.FromHexString("60ea000012020801"),
                15,
                1,
                _hostStationLocation!.ConstantId),
            40000,
            source: StationLocation.ConstantId);

        var chunks = new List<byte[]>(3);
        while (chunks.Count < 3)
        {
            var packet = WaitForPacket(
                predicate: p =>
                    p.PiaMessage?.ProtocolType == PiaProtocol.ReliableBroadcast
                    && p.PacketType == ReliableBroadcastMessageData.PacketType,
                timeout: TimeSpan.FromSeconds(5));

            if (packet is null)
            {
                Log("No reliable broadcast packet found after 5 seconds...");
                continue;
            }

            var payload = packet.PiaMessage!.Payload;
            if ((packet.PiaMessage.MessageFlags & 0x10) != 0)
            {
                payload = DecompressReliablePayload(payload);
            }

            var data = ReliableBroadcastMessageData.Parse(payload);
            if (data.FragmentIndex == chunks.Count)
            {
                chunks.Add(data.Data.ToArray());
                Log($"Received chunk {data.FragmentIndex}/3");
            }
            else
            {
                Log($"Received duplicate chunk {data.FragmentIndex}");
            }
        }

        var combined = chunks.SelectMany(static x => x).ToArray();
        if (combined.Length != TradeBroadcastPayload.PayloadLength)
            throw new InvalidOperationException($"Unexpected trade snapshot size {combined.Length}.");

        var payloadView = new TradeBroadcastPayload(combined);
        var snapshot = _saveContext.BuildSnapshot(payloadView);

        return snapshot;
    }

    private void ListenOnSocket(Socket listener, int port, CancellationToken cancellationToken)
    {
        try
        {
            listener.Bind(new IPEndPoint(IPAddress.Any, port));
            var receiveBuffer = new byte[4096];
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

            while (!cancellationToken.IsCancellationRequested)
            {
                if (!listener.Poll(250_000, SelectMode.SelectRead))
                    continue;

                var bytesReceived = listener.ReceiveFrom(receiveBuffer, SocketFlags.None, ref remote);
                var source = (IPEndPoint)remote;
                if (source.Address.Equals(StationLocation.PrivateAddress.Address))
                    continue;

                var payload = receiveBuffer.AsMemory(0, bytesReceived).ToArray();
                if (payload.Length >= 4 && payload.AsSpan(0, 4).SequenceEqual(new byte[] { 0x32, 0xAB, 0x98, 0x64 }))
                {
                    if (_sessionKey.Length == 0)
                    {
                        Log("Encrypted packet received before session handshake");
                        continue;
                    }

                    try
                    {
                        var piaPacket = PiaPacket.Parse(payload);
                        var messages = piaPacket.DecryptMessages(source.Address, _sessionKey);
                        lock (_queueLock)
                        {
                            _packetQueue.AddRange(messages.Select(message => new Packet(message, piaPacket.ConnectionId, piaPacket.PacketId)));
                            Monitor.PulseAll(_queueLock);
                        }
                    }
                    catch (CryptographicException)
                    {
                        Log("Failed to decrypt packet");
                    }
                    catch (InvalidOperationException)
                    {
                        Log("Failed to parse packet");
                    }
                }
                else
                {
                    lock (_queueLock)
                    {
                        _packetQueue.Add(new Packet(payload));
                        Monitor.PulseAll(_queueLock);
                    }
                }
            }
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException ex) when (cancellationToken.IsCancellationRequested && ex.SocketErrorCode is SocketError.Interrupted or SocketError.OperationAborted or SocketError.NotSocket)
        {
            // Expected during shutdown.
        }
    }

    private bool WaitForAck(uint ackId, TimeSpan timeout)
    {
        return WaitForPacket(packet => IsMatchingAck(packet, ackId), timeout) is not null;

        static bool IsMatchingAck(Packet packet, uint expectedAckId)
        {
            if (!packet.IsPia || packet.PacketType != Ack.PacketType)
                return false;

            return Ack.Parse(packet.PiaMessage!.Payload).AckId == expectedAckId;
        }
    }

    private Packet? WaitForPacket(Func<Packet, bool> predicate, TimeSpan? timeout)
    {
        var end = timeout.HasValue ? DateTime.UtcNow + timeout.Value : DateTime.MaxValue;
        lock (_queueLock)
        {
            while (true)
            {
                for (var index = 0; index < _packetQueue.Count; index++)
                {
                    if (!predicate(_packetQueue[index]))
                        continue;

                    var match = _packetQueue[index];
                    _packetQueue.RemoveAt(index);
                    return match;
                }

                if (timeout.HasValue)
                {
                    var remaining = end - DateTime.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                        return null;

                    Monitor.Wait(_queueLock, remaining);
                }
                else
                {
                    Monitor.Wait(_queueLock);
                }
            }
        }
    }

    private void BroadcastPacket(IByteSerializable packet, int port)
    {
        _socket.SendTo(packet.ToArray(), new IPEndPoint(IPAddress.Broadcast, port));
    }

    private void SendPiaPayload(IPiaPayload payload, int port = 0, ulong destination = 0, ulong source = 0, byte? connectionId = null, ushort? packetId = null)
    {
        EnsureMatchmade();
        var message = PiaMessage.FromPayload(payload, port, destination, source);
        var piaPacket = PiaPacket.FromMessage(message, connectionId ?? _connectionId, packetId ?? GeneratePacketId(), new byte[12], StationLocation.PrivateAddress.Address, _sessionKey);
        _socket.SendTo(piaPacket.ToArray(), _sessionInfo!.HostAddress);
    }

    private void BroadcastPiaPayload(IPiaPayload payload, int port, int piaPort = 0, ulong destination = 0, ulong source = 0, byte? connectionId = null, ushort? packetId = null)
    {
        EnsureMatchmade();
        var message = PiaMessage.FromPayload(payload, piaPort, destination, source);
        var piaPacket = PiaPacket.FromMessage(message, connectionId ?? _connectionId, packetId ?? GeneratePacketId(), new byte[12], StationLocation.PrivateAddress.Address, _sessionKey);
        _socket.SendTo(piaPacket.ToArray(), new IPEndPoint(IPAddress.Broadcast, port));
    }

    private static ReadOnlyMemory<byte> DecompressReliablePayload(ReadOnlyMemory<byte> payload)
    {
        var prefix = payload[..12].ToArray();
        using var compressedStream = new MemoryStream(payload[12..].ToArray());
        using var zlib = new ZLibStream(compressedStream, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return prefix.Concat(output.ToArray()).ToArray();
    }

    private static IPAddress ResolveLocalIpAddress()
    {
        var hostName = Dns.GetHostName();
        var addresses = Dns.GetHostAddresses(hostName);
        var ipv4 = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);
        if (ipv4 is null)
            throw new InvalidOperationException("No IPv4 address found for local host.");

        return ipv4;
    }

    private ushort GeneratePacketId()
    {
        _packetIdCounter++;
        if (_packetIdCounter == 0)
            _packetIdCounter = 1;

        return _packetIdCounter;
    }

    private byte GenerateConnectionId()
    {
        return (byte)Random.Shared.Next(1, 256);
    }

    private uint GenerateAcknowledgementId()
    {
        _ackCounter++;
        return _ackCounter;
    }

    private void EnsureMatchmade()
    {
        if (_sessionInfo is null || _sessionKey.Length == 0)
            throw new InvalidOperationException("Trade client has not completed matchmaking yet.");
    }

    private void EnsureTradeReady()
    {
        if (_sessionInfo is null || _hostStationLocation is null || _sessionKey.Length == 0)
            throw new InvalidOperationException("Trade client is not matched to a host session yet.");
    }

    private void ClearPacketQueue()
    {
        lock (_queueLock)
            _packetQueue.Clear();
    }

    private static Socket CreateListenerSocket(int _)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
        return socket;
    }

    public void Dispose()
    {
        _listenerCancellation.Cancel();

        foreach (var socket in _listenerSockets)
            socket.Dispose();

        try
        {
            Task.WaitAll([.. _listenerTasks], TimeSpan.FromSeconds(1));
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is SocketException or ObjectDisposedException))
        {
            // Expected during shutdown.
        }

        _socket.Dispose();
        _listenerCancellation.Dispose();
    }
}
