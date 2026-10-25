// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// BACnet, building automation. Own procedure, because it runs over UDP
    /// and goes beyond a yes/no answer: the properties of the device (object
    /// number, vendor, name) are queried and then written to the port log.
    /// </summary>
    public sealed class BacNetProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.BacNet;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [47808];


        /// <summary>
        /// ReadProperty for the object name of the device: the same packet that
        /// <see cref="QueryBacnetProperty"/> uses for every further property,
        /// with property 0x4D.
        /// <para>
        /// Every part must be encoded correctly: the NPDU needs the "expecting
        /// reply" bit (0x04), the APDU needs its complete header (PDU type,
        /// maximum APDU size and invoke ID, ASHRAE 135, clause 20.1.2), the
        /// object identifier must name type 8 (Device) and the property must
        /// be 0x4D (Object_Name).
        /// </para>
        /// <para>
        /// A malformed packet is not reliably answered: one reference
        /// implementation discards it silently, so <c>GetBacNetInfos</c> ends
        /// before the property loop and reports "no response" although the
        /// device answers the following packets completely. Another answers
        /// with a Reject, reason 9 ("unrecognized service"), which also starts
        /// with 0x81 and passes <see cref="IsBacNet"/>. Detection would then
        /// depend on whether a device answers an invalid packet at all.
        /// </para>
        /// <para>
        /// Verified against two reference implementations: the object name
        /// comes back in a Complex-ACK.
        /// </para>
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x81, 0x0A,             // BVLC: BACnet/IP, Original-Unicast-NPDU
                0x00, 0x11,             // total length including the BVLC header (17 bytes)
                0x01, 0x04,             // NPDU: version 1, "expecting reply"
                0x00, 0x05, 0x01, 0x0C, // APDU: Confirmed-Request, max. APDU, invoke ID 1, ReadProperty
                0x0C, 0x02, 0x3F, 0xFF, 0xFF, // object: type 8 (Device), instance 4194303 = "this device"
                0x19, 0x4D              // property 0x4D (Object_Name)
            };
        /// <summary>The properties queried one by one after the first answer.</summary>
        private static readonly List<byte> PropertyIds = new List<byte>
        {
            0x4B, // Device ID
            0x78, // Vendor
            0x79, // Vendor Name
            0x2C, // Firmware Revision
            0x0C, // Application Software
            0x4D, // Object Name
            0x46, // Model Name
            0x1C, // Description
            0x3A  // Location
        };

        public override Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            return GetBacNetInfos(address, port, Hello);
        }

        /// <summary>
        /// First the ReadProperty request; if an answer arrives, the device is
        /// queried property by property.
        /// </summary>
        private static async Task<PortResult> GetBacNetInfos(string targetIP, int targetPort, byte[] bacnetRequestPacket)
        {
            PortResult portResult = new PortResult { Ports = new List<int> { targetPort }, Status = PortStatus.NoResponse };
            Dictionary<string, string> collectedData = new Dictionary<string, string>();

            try
            {
                using (UdpClient udpClient = new UdpClient())
                {
                    IPEndPoint targetEndPoint = new IPEndPoint(IPAddress.Parse(targetIP), targetPort);

                    // Send the packet first
                    await udpClient.SendAsync(bacnetRequestPacket, bacnetRequestPacket.Length, targetEndPoint);

                    // Wait for the answer
                    using var cts = new CancellationTokenSource(3000);
                    var receiveTask = udpClient.ReceiveAsync();

                    if (await Task.WhenAny(receiveTask, Task.Delay(2000, cts.Token)) == receiveTask)
                    {
                        // This line must stay even where the value is not
                        // needed below.
                        //
                        // WhenAny also completes with receiveTask when the
                        // receive has *failed*, and the most common failure is
                        // the ICMP "port unreachable" answer of a host on which
                        // no BACnet listens. Only accessing the result throws
                        // the exception, and only that keeps the status at "no
                        // response". Without it, the rejection itself counts as
                        // a finding, and ordinary workstations are reported as
                        // BACnet devices.
                        byte[] response = receiveTask.Result.Buffer;

                        // The answer must also look like BACnet.
                        //
                        // Every BACnet/IP packet starts with the BVLC type 0x81,
                        // followed by the function and the total length in two
                        // bytes (ASHRAE 135, Annex J). Without this check any
                        // datagram arriving at this socket would count, and
                        // "running" would only mean "something arrived".
                        if (!IsBacNet(response))
                        {
                            portResult.Status = PortStatus.NoResponse;
                            portResult.PortLog = "Antwort kam, ist aber kein BACnet (keine BVLC-Kennung 0x81).";
                            return portResult;
                        }

                        // First answer received; now collect the further information
                        foreach (byte propertyId in PropertyIds)
                        {
                            byte[]? value = await QueryBacnetProperty(udpClient, targetEndPoint, propertyId);
                            if (PropertyIdToName(propertyId) == "ObjectID")
                            {
                                collectedData[PropertyIdToName(propertyId)] = ExtractBacnetObjectInstanceAsString("ObjectID", value);
                            }
                            else if (PropertyIdToName(propertyId) == "VendorID")
                            {
                                collectedData[PropertyIdToName(propertyId)] = ExtractBacnetObjectInstanceAsString("VendorID", value);
                            }
                            else
                            {
                                collectedData[PropertyIdToName(propertyId)] = ExtractBacnetAsciiString(value);
                            }
                        }

                        portResult.Status = PortStatus.IsRunning;

                        // The collected information goes into the port log,
                        // where the details view reads it.
                        portResult.PortLog = FormatDeviceInfo(collectedData);
                    }
                    else
                    {
                        portResult.Status = PortStatus.NoResponse;
                    }
                }
            }
            catch (Exception)
            {
                // No BACnet device or no answer; not an error.
            }

            return portResult;
        }

        /// <summary>
        /// The queried properties as text, one per line.
        /// <para>
        /// Empty values are left out: not every device maintains location or
        /// description, and an empty "Location:" line says less than none. An
        /// object number 0 means the answer could not be evaluated and also
        /// counts as empty.
        /// </para>
        /// </summary>
        private static string FormatDeviceInfo(Dictionary<string, string> collectedData)
        {
            List<string> lines = [];

            foreach (KeyValuePair<string, string> entry in collectedData)
            {
                string value = entry.Value?.Trim() ?? string.Empty;

                if (value.Length == 0) continue;
                if (value == "0" && entry.Key is "ObjectID" or "VendorID") continue;

                lines.Add($"{entry.Key}: {value}");
            }

            return string.Join(Environment.NewLine, lines);
        }

        private static string PropertyIdToName(byte propertyId)
        {
            return propertyId switch
            {
                0x4B => "ObjectID",
                0x78 => "VendorID",
                0x79 => "Vendor Name",
                0x2C => "Firmware Revision",
                0x0C => "Application Software",
                0x4D => "Object Name",
                0x46 => "Model Name",
                0x1C => "Description",
                0x3A => "Location",
                _ => $"Unbekannte Property (0x{propertyId:X2})"
            };
        }

        /// <summary>Object and vendor numbers are numeric in the packet, not text.</summary>
        private static string ExtractBacnetObjectInstanceAsString(string BacNetPropertie, byte[]? data)
        {
            int ID = 0;
            if (data == null) return ID.ToString();

            if (BacNetPropertie == "ObjectID")
            {
                // Bytes 20, 21, 22 (index 19, 20, 21)
                int byte20 = data[19];
                int byte21 = data[20];
                int byte22 = data[21];

                // Combine the 22-bit instance number from the 3 bytes
                ID = ((byte20 & 0x3F) << 16) | (byte21 << 8) | byte22;
            }
            if (BacNetPropertie == "VendorID")
            {
                // The vendor ID is in the second-to-last byte of the packet
                int byte2 = data[data.Length - 2];
                ID = byte2;
            }

            return ID.ToString();
        }

        /// <summary>
        /// Text values follow the tag 0x75, preceded by a length byte.
        /// <para>
        /// The length byte is followed by the character set number and only
        /// then by the text; the length includes that byte. Read as the first
        /// character, it would start every value with a null character, shown
        /// as a box or a gap before the actual text. Note that
        /// <c>Replace("\\0", "")</c> does not help: it searches for a backslash
        /// followed by a zero as two characters, not for the null character.
        /// </para>
        /// </summary>
        private static string ExtractBacnetAsciiString(byte[]? data)
        {
            if (data == null || data.Length < 20)
                return string.Empty;

            int index = data.ToList().IndexOf(117); // 0x75, the character string tag
            if (index == -1 || index + 2 >= data.Length)
                return string.Empty; // no string found

            int length = data[index + 1]; // the next byte is the length of the string
            if (index + 2 + length > data.Length)
                return string.Empty; // invalid length

            // Skip the character set byte; it counts towards the length but is
            // not part of the text.
            if (length < 1) return string.Empty;

            return Encoding.ASCII.GetString(data, index + 3, length - 1).Trim('\0', ' ');
        }

        private static async Task<byte[]?> QueryBacnetProperty(UdpClient udpClient, IPEndPoint targetEndPoint, byte propertyId)
        {
            byte[] requestPacket = new byte[]
            {
                0x81, 0x0A,  // BVLC: BACnet/IP, Original-Unicast-NPDU
                0x00, 0x11,  // total length including the BVLC header (17 bytes)
                0x01, 0x04,  // NPDU: version 1, "expecting reply"
                0x00, 0x05,  // APDU: Confirmed-Request, maximum APDU size
                0x01, 0x0C,  // invoke ID 1, service choice 0x0C (ReadProperty)
                0x0C, 0x02, 0x3F, 0xFF, 0xFF, // object: type 8 (Device), instance 4194303 = "this device"
                0x19, propertyId              // the requested property
            };

            await udpClient.SendAsync(requestPacket, requestPacket.Length, targetEndPoint);

            // Wait for the answer
            using var cts = new CancellationTokenSource(2000);
            var receiveTask = udpClient.ReceiveAsync();

            if (await Task.WhenAny(receiveTask, Task.Delay(2000, cts.Token)) == receiveTask)
            {
                return receiveTask.Result.Buffer;
            }

            return null;
        }

        /// <summary>
        /// An answer counts as BACnet if it starts with the BVLC type 0x81 and
        /// its length field matches the actual length.
        /// <para>
        /// The length field is in bytes 2 and 3 and counts the whole packet
        /// including the four-byte BVLC header. The check is "not larger than
        /// received": a datagram may arrive truncated, but a random byte
        /// pattern hardly meets both conditions.
        /// </para>
        /// </summary>
        public override bool Identify(byte[] response) => IsBacNet(response);

        private static bool IsBacNet(byte[] response)
        {
            if (response.Length < 4 || response[0] != 0x81) return false;

            int gemeldeteLaenge = (response[2] << 8) | response[3];

            return gemeldeteLaenge >= 4 && gemeldeteLaenge <= response.Length;
        }
    }
}
