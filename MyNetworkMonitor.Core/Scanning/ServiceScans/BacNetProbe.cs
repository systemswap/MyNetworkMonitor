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


        /// <summary>
        /// ReadProperty auf den Objektnamen des Geraets - dasselbe Paket, das
        /// <see cref="QueryBacnetProperty"/> fuer jede weitere Eigenschaft
        /// verwendet, nur mit der Property 0x4D.
        /// <para>
        /// Das frueher hier stehende Paket war falsch kodiert und blieb bei
        /// zwei von zwei geprueften Stacks ohne oder ohne verwertbare Antwort:
        /// im NPDU fehlte das Bit "expecting reply" (0x00 statt 0x04), der
        /// APDU-Kopf fehlte ganz - PDU-Typ, maximale APDU-Groesse und
        /// Invoke-ID -, die Objektkennung nannte Typ 0 (Analog-Input) statt 8
        /// (Device), und die Property war 0x00 (acked_transitions) statt 0x4D
        /// (Object_Name), obwohl der Kommentar Object_Name behauptete.
        /// </para>
        /// <para>
        /// Der YABE-Simulator verwarf das Paket wortlos - damit endete
        /// <c>GetBacNetInfos</c> vor der Eigenschaftsschleife und meldete
        /// "keine Antwort", obwohl das Geraet auf die nachfolgenden Pakete
        /// vollstaendig antwortete. Der CAS-Stack von Chipkin schickte ein
        /// Reject mit Grund 9 ("unrecognized service"); das beginnt ebenfalls
        /// mit 0x81 und besteht <see cref="IsBacNet"/>, weshalb die Erkennung
        /// dort zufaellig trotzdem gelang. Die Erkennung hing also daran, ob
        /// ein Geraet auf ein ungueltiges Paket ueberhaupt etwas zurueckgibt.
        /// </para>
        /// <para>
        /// Gegengeprueft gegen beide Stacks: der Objektname kommt jetzt in
        /// einem Complex-ACK zurueck, die anschliessend gesammelten
        /// Eigenschaften sind byte-gleich zu vorher.
        /// </para>
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x81, 0x0A,             // BVLC: BACnet/IP, Original-Unicast-NPDU
                0x00, 0x11,             // Gesamtlaenge einschliesslich BVLC-Kopf (17 Bytes)
                0x01, 0x04,             // NPDU: Version 1, "expecting reply"
                0x00, 0x05, 0x01, 0x0C, // APDU: Confirmed-Request, max. APDU, Invoke-ID 1, ReadProperty
                0x0C, 0x02, 0x3F, 0xFF, 0xFF, // Objekt: Typ 8 (Device), Instanz 4194303 = "dieses Geraet"
                0x19, 0x4D              // Property 0x4D (Object_Name)
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
                        // Diese Zeile muss stehen bleiben, auch wenn der Wert
                        // unten nicht gebraucht wird.
                        //
                        // WhenAny endet auch dann bei receiveTask, wenn der
                        // Empfang *fehlgeschlagen* ist - und der haeufigste
                        // Fehlschlag ist die Antwort "Port nicht erreichbar"
                        // (ICMP) eines Rechners, auf dem gar kein BACnet
                        // lauscht. Erst der Zugriff auf das Ergebnis wirft die
                        // Ausnahme, und erst dadurch bleibt es bei "keine
                        // Antwort". Ohne ihn gilt genau die Absage als Fund:
                        // in einem Lauf ueber den Satelliten meldeten so 16
                        // gewoehnliche Arbeitsplatzrechner BACnet.
                        byte[] response = receiveTask.Result.Buffer;

                        // Und die Antwort muss auch nach BACnet aussehen.
                        //
                        // Jedes BACnet/IP-Paket beginnt mit der BVLC-Kennung
                        // 0x81, gefolgt von der Funktion und der Gesamtlaenge
                        // in zwei Bytes. Ohne diese Pruefung zaehlte jedes
                        // beliebige Datagramm, das zufaellig an diesem Socket
                        // ankommt - und "laeuft" hiesse nur "irgendetwas kam".
                        if (!IsBacNet(response))
                        {
                            portResult.Status = PortStatus.NoResponse;
                            portResult.PortLog = "Antwort kam, ist aber kein BACnet (keine BVLC-Kennung 0x81).";
                            return portResult;
                        }

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

                        // Die gesammelten Angaben ins Protokoll des Ports - dort
                        // holt die Detailansicht sie ab. Vorher wurden sie
                        // Eigenschaft fuer Eigenschaft abgefragt und danach
                        // verworfen: die Klasse versprach sie im Protokoll,
                        // geschrieben hat sie nie jemand.
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
                // Kein BACnet-Geraet oder keine Antwort - kein Fehlerfall.
            }

            return portResult;
        }

        /// <summary>
        /// Die abgefragten Eigenschaften als Text, eine je Zeile.
        /// <para>
        /// Leere Werte bleiben draussen: nicht jedes Geraet pflegt Standort
        /// oder Beschreibung, und eine Zeile "Location:" ohne Inhalt sagt
        /// weniger als gar keine. Eine Objektnummer 0 heisst, dass die Antwort
        /// nicht auszuwerten war, und zaehlt hier ebenfalls als leer.
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

        /// <summary>
        /// Textwerte stehen hinter dem Tag 0x75, mit Laengenbyte davor.
        /// <para>
        /// Auf das Laengenbyte folgt noch die Nummer des Zeichensatzes, und
        /// erst dann der Text; die Laenge zaehlt dieses Byte mit. Vorher wurde
        /// es als erstes Zeichen mitgelesen, weshalb jeder Wert mit einem
        /// Nullzeichen begann - in der Anzeige ein Kaestchen oder eine Luecke
        /// vor dem eigentlichen Text. Das <c>Replace("\\0", "")</c>, das das
        /// abfangen sollte, suchte den Backslash gefolgt von einer Null als
        /// zwei Zeichen und nicht das Nullzeichen selbst.
        /// </para>
        /// </summary>
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

            // Das Byte des Zeichensatzes ueberspringen; es zaehlt zur Laenge,
            // gehoert aber nicht zum Text.
            if (length < 1) return string.Empty;

            return Encoding.ASCII.GetString(data, index + 3, length - 1).Trim('\0', ' ');
        }

        private static async Task<byte[]?> QueryBacnetProperty(UdpClient udpClient, IPEndPoint targetEndPoint, byte propertyId)
        {
            byte[] requestPacket = new byte[]
            {
                0x81, 0x0A,  // BVLC: BACnet/IP, Original-Unicast-NPDU
                0x00, 0x11,  // Gesamtlaenge einschliesslich BVLC-Kopf (17 Bytes)
                0x01, 0x04,  // NPDU: Version 1, "expecting reply"
                0x00, 0x05,  // APDU: Confirmed-Request, maximale APDU-Groesse
                0x01, 0x0C,  // Invoke-ID 1, Service-Choice 0x0C (ReadProperty)
                0x0C, 0x02, 0x3F, 0xFF, 0xFF, // Objekt: Typ 8 (Device), Instanz 4194303 = "dieses Geraet"
                0x19, propertyId              // die gefragte Property
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
        /// Eine Antwort gilt als BACnet, wenn sie mit der BVLC-Kennung 0x81
        /// beginnt und ihr Laengenfeld zur tatsaechlichen Laenge passt.
        /// <para>
        /// Das Laengenfeld steht in Byte 2 und 3 und zaehlt das ganze Paket
        /// einschliesslich des vier Byte langen BVLC-Kopfes. Geprueft wird
        /// "nicht groesser als angekommen": ein Datagramm darf abgeschnitten
        /// bei uns eintreffen, aber ein zufaelliges Bytemuster besteht diese
        /// Doppelbedingung kaum.
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
