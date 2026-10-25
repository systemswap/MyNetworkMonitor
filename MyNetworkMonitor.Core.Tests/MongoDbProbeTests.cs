// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Buffers.Binary;
using System.Text;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="MongoDbProbe.Identify"/>: replies of different server versions (docs/FEHLERGEDAECHTNIS.md, No. 22).</summary>
public class MongoDbProbeTests
{
    private static readonly MongoDbProbe Probe = new();

    /// <summary>A BSON document from (type, name, value) fields; values are bool, int or string.</summary>
    private static byte[] Bson(params (string Name, object Value)[] fields)
    {
        var body = new List<byte>();
        foreach (var (name, value) in fields)
        {
            byte type = value switch { bool => 0x08, int => 0x10, string => 0x02, _ => throw new ArgumentException(name) };
            body.Add(type);
            body.AddRange(Encoding.ASCII.GetBytes(name));
            body.Add(0);
            switch (value)
            {
                case bool b: body.Add(b ? (byte)1 : (byte)0); break;
                case int i: body.AddRange(BitConverter.GetBytes(i)); break;
                case string t:
                    body.AddRange(BitConverter.GetBytes(Encoding.UTF8.GetByteCount(t) + 1));
                    body.AddRange(Encoding.UTF8.GetBytes(t));
                    body.Add(0);
                    break;
            }
        }
        body.Add(0);
        return [.. BitConverter.GetBytes(body.Count + 4), .. body];
    }

    /// <summary>An OP_REPLY (or OP_MSG) to request 1 carrying the document.</summary>
    private static byte[] Reply(byte[] document, int opCode = 1, int responseTo = 1)
    {
        byte[] prefix = opCode == 1 ? new byte[20] : new byte[5];   // OP_REPLY: flags, cursorID, startingFrom, numberReturned; OP_MSG: flags, section kind
        if (opCode == 1) BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(16), 1);
        byte[] message = new byte[16 + prefix.Length + document.Length];
        BinaryPrimitives.WriteInt32LittleEndian(message, message.Length);
        BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(4), 99);
        BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(8), responseTo);
        BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(12), opCode);
        prefix.CopyTo(message, 16);
        document.CopyTo(message, 16 + prefix.Length);
        return message;
    }

    public static TheoryData<string, byte[]> Servers => new()
    {
        { "4.0 standalone", Reply(Bson(("ismaster", true), ("maxBsonObjectSize", 16777216), ("maxWireVersion", 7), ("minWireVersion", 0), ("ok", 1))) },
        { "4.4 with helloOk", Reply(Bson(("helloOk", true), ("ismaster", true), ("topologyVersion", "x"), ("maxWireVersion", 9), ("ok", 1))) },
        { "7.0 replica set secondary", Reply(Bson(("ismaster", false), ("secondary", true), ("setName", "rs-example"), ("me", "db2.example:27017"), ("maxWireVersion", 21), ("ok", 1))) },
        { "8.0 as OP_MSG", Reply(Bson(("isWritablePrimary", true), ("maxWireVersion", 25), ("ok", 1)), opCode: 2013) },
    };

    [Theory]
    [MemberData(nameof(Servers))]
    public void Identify_RecognisesServersOfAnyVersion(string server, byte[] reply)
    {
        Assert.True(Probe.Identify(reply), server);
    }

    [Fact]
    public void Identify_AcceptsAReplyCutOffByTheReadBuffer()
    {
        byte[] reply = Reply(Bson(("ismaster", true), ("maxWireVersion", 17), ("ok", 1), ("padding", new string('p', 200))));
        Assert.True(Probe.Identify(reply[..^150]));
    }

    [Fact]
    public void Identify_RejectsOtherAnswers()
    {
        byte[] document = Bson(("ismaster", true), ("maxWireVersion", 21), ("ok", 1));
        Assert.False(Probe.Identify(Reply(document, responseTo: 2)), "answer to another request");
        Assert.False(Probe.Identify(Reply(document, opCode: 2004)), "a query, not a reply");
        Assert.False(Probe.Identify(Reply(Bson(("ok", 0), ("errmsg", "no such command")))), "no isMaster fields");
        Assert.False(Probe.Identify(Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\\r\\n\\r\\nismaster maxWireVersion")), "text that mentions the fields");
        Assert.False(Probe.Identify([0x49, 0x01, 0x00, 0x00]), "the bare header that used to be enough");
        Assert.False(Probe.Identify([]));
    }
}
