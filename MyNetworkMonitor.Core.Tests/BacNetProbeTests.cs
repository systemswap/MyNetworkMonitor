// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>The values of a BACnet device from its answers (docs/FEHLERGEDAECHTNIS.md, No. 30).</summary>
public class BacNetProbeTests
{
    /// <summary>A ComplexACK of the given length: BVLC, NPDU version 1, APDU type 3.</summary>
    private static byte[] Ack(int length)
    {
        byte[] answer = new byte[length];
        answer[0] = 0x81; answer[1] = 0x0A; answer[2] = (byte)(length >> 8); answer[3] = (byte)length;
        answer[4] = 0x01; answer[6] = 0x30;
        return answer;
    }

    /// <summary>A Reject (APDU type 6) with reason 9: BACnet, but without a value.</summary>
    private static readonly byte[] Reject = [0x81, 0x0A, 0x00, 0x09, 0x01, 0x00, 0x60, 0x01, 0x09];

    [Fact]
    public void ObjectAndVendor_AreReadFromAComplexAck()
    {
        byte[] objectId = Ack(24);
        objectId[19] = 0x02; objectId[20] = 0x01; objectId[21] = 0x02;
        Assert.Equal("131330", BacNetProbe.ExtractBacnetObjectInstanceAsString("ObjectID", objectId));

        byte[] vendor = Ack(20);
        vendor[18] = 7;
        Assert.Equal("7", BacNetProbe.ExtractBacnetObjectInstanceAsString("VendorID", vendor));
    }

    [Fact]
    public void Reject_CarriesNoVendor()
    {
        Assert.Equal("0", BacNetProbe.ExtractBacnetObjectInstanceAsString("VendorID", Reject));
        Assert.Equal("0", BacNetProbe.ExtractBacnetObjectInstanceAsString("ObjectID", Reject));
    }

    [Fact]
    public void ShortAnswer_YieldsNoNumberInsteadOfAnException()
    {
        Assert.Equal("0", BacNetProbe.ExtractBacnetObjectInstanceAsString("ObjectID", Ack(12)));
    }

    [Fact]
    public void Text_IsReadAfterTheCharacterSet()
    {
        byte[] answer = Ack(30);
        answer[20] = 0x75; answer[21] = 6; answer[22] = 0x00;   // tag, length incl. character set, ANSI X3.4
        Encoding.ASCII.GetBytes("AHU-3").CopyTo(answer, 23);
        Assert.Equal("AHU-3", BacNetProbe.ExtractBacnetAsciiString(answer));

        answer[6] = 0x60;                                       // the same bytes as a Reject
        Assert.Equal(string.Empty, BacNetProbe.ExtractBacnetAsciiString(answer));
    }

    [Fact]
    public void NpduWithSourceAddress_IsSkipped()
    {
        // control 0x08: source network (2), length (1) and a 6-byte address
        // come before the APDU.
        byte[] answer = new byte[30];
        answer[0] = 0x81; answer[3] = 30; answer[4] = 0x01; answer[5] = 0x08; answer[8] = 6;
        answer[15] = 0x30;
        Assert.True(BacNetProbe.IsComplexAck(answer));
        answer[15] = 0x50;                                      // Error
        Assert.False(BacNetProbe.IsComplexAck(answer));
    }
}
