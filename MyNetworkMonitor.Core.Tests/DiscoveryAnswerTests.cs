// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// Reading the answers of SSDP, ONVIF and mDNS (docs/FEHLERGEDAECHTNIS.md, No. 32). Made-up
/// answers, documentation addresses.
/// </summary>
public class DiscoveryAnswerTests
{
    // ------------------------------------------------------------------ SSDP

    [Fact]
    public void Ssdp_DescriptionGivesNameManufacturerAndModel()
    {
        var device = new ScanningMethod_SSDP_UPNP.SSDPDeviceInfo { IP = "192.0.2.10" };
        ScanningMethod_SSDP_UPNP.ParseDescription(device,
            "<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><friendlyName>Living Room</friendlyName>" +
            "<manufacturer>Example Corp</manufacturer><modelName>Box</modelName><modelNumber>2</modelNumber>" +
            "<deviceList><device><friendlyName>Inner</friendlyName></device></deviceList></device></root>");

        Assert.Equal(string.Join(Environment.NewLine, "Name: Living Room", "Manufacturer: Example Corp", "Model: Box 2"),
            device.ToDetail());
    }

    [Theory]
    [InlineData("http://192.0.2.10:49152/desc.xml", "192.0.2.10", true)]
    [InlineData("https://192.0.2.10/desc.xml", "192.0.2.10", true)]
    [InlineData("http://192.0.2.99:49152/desc.xml", "192.0.2.10", false)]   // another host
    [InlineData("http://example.com/desc.xml", "192.0.2.10", false)]        // a name, possibly on the internet
    [InlineData("ftp://192.0.2.10/desc.xml", "192.0.2.10", false)]
    [InlineData("", "192.0.2.10", false)]
    public void Ssdp_DescriptionOnlyFromTheDeviceItself(string location, string source, bool expected)
    {
        Assert.Equal(expected, ScanningMethod_SSDP_UPNP.IsOwnLocation(location, source));
    }

    // ----------------------------------------------------------------- ONVIF

    private const string ProbeMatch =
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" " +
        "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
        "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch>" +
        "<wsa:EndpointReference><wsa:Address>urn:uuid:0a1b2c3d-0000-4000-8000-000000000001</wsa:Address>" +
        "</wsa:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types>" +
        "<d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/Garden%20Cam</d:Scopes>" +
        "<d:XAddrs>{0}</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches>" +
        "</SOAP-ENV:Body></SOAP-ENV:Envelope>";

    [Fact]
    public void Onvif_SeveralServiceAddresses_TheFirstCounts()
    {
        string answer = string.Format(ProbeMatch,
            "http://192.0.2.20/onvif/device_service http://[2001:db8::20]/onvif/device_service");

        IPCamInfos? camera = ScanningMethod_ONVIF_IPCam.ParseONVIFResponse(answer, "192.0.2.20");

        Assert.NotNull(camera);
        Assert.Equal("http://192.0.2.20/onvif/device_service", camera.XAddress);
        Assert.Equal("80", camera.Port);
        Assert.Equal("Garden Cam", camera.Name);
        Assert.Equal("0a1b2c3d-0000-4000-8000-000000000001", camera.UUID);
    }

    [Fact]
    public void Onvif_WithoutServiceAddress_IsNoCamera()
    {
        string answer = ProbeMatch.Replace("<d:XAddrs>{0}</d:XAddrs>", string.Empty);
        Assert.Null(ScanningMethod_ONVIF_IPCam.ParseONVIFResponse(answer, "192.0.2.20"));
    }

    // ------------------------------------------------------------------ mDNS

    private static void Name(List<byte> p, string name)
    {
        foreach (string label in name.Split('.'))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(label);
            p.Add((byte)bytes.Length);
            p.AddRange(bytes);
        }
        p.Add(0);
    }

    private static void Record(List<byte> p, string owner, int type, byte[] data)
    {
        Name(p, owner);
        p.AddRange([(byte)(type >> 8), (byte)type, 0x00, 0x01, 0, 0, 0, 120, (byte)(data.Length >> 8), (byte)data.Length]);
        p.AddRange(data);
    }

    /// <summary>An answer that repeats the question, with a PTR answer and two address records.</summary>
    private static byte[] Answer(byte flags)
    {
        List<byte> p = [0, 0, flags, 0x00, 0, 1, 0, 1, 0, 0, 0, 2];
        Name(p, "_googlecast._tcp.local");
        p.AddRange([0x00, 0x0c, 0x00, 0x01]);
        List<byte> target = [];
        Name(target, "Living Room._googlecast._tcp.local");
        Record(p, "_googlecast._tcp.local", 0x0c, [.. target]);
        Record(p, "Other-Interface.local", 0x01, [198, 51, 100, 7]);
        Record(p, "Chromecast-1.local", 0x01, [192, 0, 2, 30]);
        return [.. p];
    }

    [Fact]
    public void Mdns_QuestionIsSkipped_AndTheSenderKeepsItsAddress()
    {
        var info = new MdnsDeviceInfo { IP = "192.0.2.30" };
        ScanningMethod_mDNS.ParseResponse(Answer(0x84), info);

        Assert.Equal("192.0.2.30", info.IP);                  // not the address of another record
        Assert.Equal("Chromecast-1", info.HostName);
        Assert.Equal("_googlecast._tcp.local", info.Service);
        Assert.Equal("Living Room", info.TargetHost);
    }

    [Fact]
    public void Mdns_QueriesAreNoAnswer()
    {
        Assert.True(ScanningMethod_mDNS.IsAnswer(Answer(0x84)));
        Assert.False(ScanningMethod_mDNS.IsAnswer(Answer(0x00)));
    }

    [Fact]
    public void Mdns_CutOffAnswers_DoNotThrow()
    {
        byte[] answer = Answer(0x84);
        for (int length = 0; length <= answer.Length; length++)
            ScanningMethod_mDNS.ParseResponse(answer[..length], new MdnsDeviceInfo { IP = "192.0.2.30" });
    }
}
