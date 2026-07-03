namespace PokePia.Protocol;

internal interface IByteSerializable
{
    byte[] ToArray();
}

internal interface IPiaPayload : IByteSerializable
{
    PiaProtocol Protocol { get; }

    byte MessageFlags { get; }
}
