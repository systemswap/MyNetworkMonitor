using System.Net;
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// BACnet, die Gebaeudeleittechnik. Eigener Ablauf, weil es ueber UDP
    /// laeuft und nicht bei einer Ja/Nein-Antwort bleibt: gefragt werden die
    /// Eigenschaften des Geraets - Objektnummer, Hersteller, Name -, und die
    /// stehen anschliessend im Protokoll des Ports.
    /// </summary>
    public sealed class BacNetProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.BacNet;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [47808];


        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x81, 0x0A,             // BACnet/IP Header
                0x00, 0x0F,             // Paketlänge (15 Bytes)
                0x01,                   // PDU-Type (Confirmed Request)
                0x00,                   // Invoke ID
                0x0C,                   // ReadProperty Service Request
                0x0C,                   // Object Type (Device)
                0x00, 0x00, 0x00, 0x01, // Device Instance (1)
                0x19, 0x00,             // Property Identifier (Object_Name)
                0x4E                    // End-Of-List
            };
        /// <summary>Die Eigenschaften, die nach der ersten Antwort einzeln nachgefragt werden.</summary>
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
        /// Erst der ReadProperty-Rundruf; kommt darauf eine Antwort, wird das
        /// Geraet Eigenschaft fuer Eigenschaft ausgefragt. Wortgleich aus
        /// <c>ScanningMethod_Services</c> uebernommen.
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

                    // Zuerst das Paket senden
                    await udpClient.SendAsync(bacnetRequestPacket, bacnetRequestPacket.Length, targetEndPoint);

                    // Auf Antwort warten
                    using var cts = new CancellationTokenSource(3000);
                    var receiveTask = udpClient.ReceiveAsync();

                    if (await Task.WhenAny(receiveTask, Task.Delay(2000, cts.Token)) == receiveTask)
                    {
                        // Erste Antwort erhalten - jetzt die weiteren Infos sammeln
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
                    }
                    else
                    {
                        portResult.Status = PortStatus.NoResponse;
                    }
                }
            }
            catch (Exception)
            {
                // Kein BACnet-Geraet oder keine Antwort - kein Fehlerfall.
            }

            return portResult;
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

        /// <summary>Objekt- und Herstellernummer stehen als Zahl im Paket, nicht als Text.</summary>
        private static string ExtractBacnetObjectInstanceAsString(string BacNetPropertie, byte[]? data)
        {
            int ID = 0;
            if (data == null) return ID.ToString();

            if (BacNetPropertie == "ObjectID")
            {
                // Bytes 20, 21, 22 (Index 19, 20, 21)
                int byte20 = data[19];
                int byte21 = data[20];
                int byte22 = data[21];

                // 22-Bit-Wert aus den 3 Bytes zusammenfuegen
                ID = ((byte20 & 0x3F) << 16) | (byte21 << 8) | byte22;
            }
            if (BacNetPropertie == "VendorID")
            {
                // Vendor-ID steht im vorletzten Byte des Pakets
                int byte2 = data[data.Length - 2];
                ID = byte2;
            }

            return ID.ToString();
        }

        /// <summary>Textwerte stehen hinter dem Tag 0x75, mit Laengenbyte davor.</summary>
        private static string ExtractBacnetAsciiString(byte[]? data)
        {
            if (data == null || data.Length < 20)
                return string.Empty;

            int index = data.ToList().IndexOf(117); // 0x75, das ASCII-String-Tag
            if (index == -1 || index + 2 >= data.Length)
                return string.Empty; // Falls kein String gefunden wurde

            int length = data[index + 1]; // Das naechste Byte gibt die Laenge des Strings an
            if (index + 2 + length > data.Length)
                return string.Empty; // Falls Laenge fehlerhaft ist

            return Encoding.ASCII.GetString(data, index + 2, length).Trim().Replace("\\0", "");
        }

        private static async Task<byte[]?> QueryBacnetProperty(UdpClient udpClient, IPEndPoint targetEndPoint, byte propertyId)
        {
            byte[] requestPacket = new byte[]
            {
                0x81, 0x0A,  // BACnet/IP Header
                0x00, 0x11,  // Paketlaenge (17 Bytes)
                0x01,        // PDU-Type: Complex-ACK (Antwort auf eine ReadProperty-Anfrage)
                0x04,        // Invoke ID (Antwort auf die Anfrage mit ID 4)
                0x00,        // Service Choice: ReadProperty Response
                0x05,        // Anzahl der Objekte: 1
                0x01, 0x0C,  // Object Type: Device (0x0C = 12)
                0x0C,        // Object Instance (Device ID)
                0x02,        // Anzahl der Properties: 2
                0x3F, 0xFF, 0xFF,  // Property Identifier (Fehler oder unbekannte Property)
                0x19,        // Property Data (muss weiter analysiert werden)
                propertyId   // Property Identifier
            };

            await udpClient.SendAsync(requestPacket, requestPacket.Length, targetEndPoint);

            // Warte auf die Antwort
            using var cts = new CancellationTokenSource(2000);
            var receiveTask = udpClient.ReceiveAsync();

            if (await Task.WhenAny(receiveTask, Task.Delay(2000, cts.Token)) == receiveTask)
            {
                return receiveTask.Result.Buffer;
            }

            return null;
        }

        /// <summary>
        /// Dieser Dienst hat keine eigene Antwortsignatur - er wird ueber
        /// seinen eigenen Ablauf erkannt, nicht ueber ein Bytemuster. Es bleibt
        /// bei der alten Regel fuer solche Faelle: eine Antwort zaehlt.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
