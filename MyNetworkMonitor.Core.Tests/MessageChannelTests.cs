// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using MyNetworkMonitor.Core.SatelliteLink;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="MessageChannel"/>: framing, compression and the limits (docs/FEHLERGEDAECHTNIS.md, No. 20).</summary>
public class MessageChannelTests
{
    /// <summary>A frame as <see cref="MessageChannel"/> writes it: 4-byte length with the top bit for gzip, then the payload.</summary>
    private static byte[] Frame(byte[] payload, bool compressed)
    {
        byte[] frame = new byte[4 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)payload.Length | (compressed ? 0x8000_0000u : 0));
        payload.CopyTo(frame, 4);
        return frame;
    }

    [Fact]
    public async Task LargeMessage_RoundTripsCompressed()
    {
        var message = new SatelliteMessage { Type = "test", Name = new string('x', 100_000) };
        using MemoryStream wire = new();
        await new MessageChannel(wire).SendAsync(message, CancellationToken.None);

        Assert.True((wire.GetBuffer()[0] & 0x80) != 0, "a payload above the threshold is sent compressed");
        Assert.True(wire.Length < 10_000);

        wire.Position = 0;
        SatelliteMessage? received = await new MessageChannel(wire).ReceiveAsync(CancellationToken.None);
        Assert.Equal(message.Name, received?.Name);
    }

    [Fact]
    public async Task GzipBomb_IsRejectedBeforeItFillsMemory()
    {
        // Valid JSON whose text field alone is larger than the limit; packed it is a few hundred kilobytes.
        using MemoryStream packed = new();
        using (GZipStream gzip = new(packed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write("{\"Type\":\"test\",\"Name\":\""u8);
            byte[] filler = new byte[1024 * 1024];
            Array.Fill(filler, (byte)'A');
            for (int i = 0; i <= MessageChannel.MaxPlainBytes / filler.Length; i++) gzip.Write(filler);
            gzip.Write("\"}"u8);
        }
        Assert.True(packed.Length < MessageChannel.MaxMessageBytes, "the frame itself is within the frame limit");

        using MemoryStream wire = new(Frame(packed.ToArray(), compressed: true));
        await Assert.ThrowsAsync<InvalidDataException>(() => new MessageChannel(wire).ReceiveAsync(CancellationToken.None));
    }

    [Fact]
    public async Task AnnouncedLengthAboveLimit_IsRejected()
    {
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, MessageChannel.MaxMessageBytes + 1u);
        using MemoryStream wire = new(header);
        await Assert.ThrowsAsync<InvalidDataException>(() => new MessageChannel(wire).ReceiveAsync(CancellationToken.None));
    }

    [Fact]
    public async Task CleanCloseBetweenMessages_ReturnsNull()
    {
        using MemoryStream wire = new();
        Assert.Null(await new MessageChannel(wire).ReceiveAsync(CancellationToken.None));
    }

    [Fact]
    public async Task UncompressedFrame_IsRead()
    {
        using MemoryStream wire = new(Frame(Encoding.UTF8.GetBytes("{\"Type\":\"ping\",\"ProtocolVersion\":3}"), compressed: false));
        SatelliteMessage? received = await new MessageChannel(wire).ReceiveAsync(CancellationToken.None);
        Assert.Equal("ping", received?.Type);
        Assert.Equal(3, received?.ProtocolVersion);
    }
}
