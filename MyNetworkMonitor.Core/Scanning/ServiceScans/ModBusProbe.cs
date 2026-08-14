using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Modbus TCP. Steuerungen dieser Art vertragen wenig - darum eine
    /// Verbindung, eine Anfrage, fertig.
    /// </summary>
    public sealed class ModBusProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.ModBus;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [502];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Modbus TCP-Erkennung
            if (service == ServiceType.ModBus)
            {
                // Modbus TCP Header besteht aus 7 Bytes, der Funktionscode ist das
                // erste Byte danach - also Index 7, und der ist nur gueltig zu lesen,
                // wenn die Antwort mindestens 8 Byte lang ist. Mit ">= 7" warf response[7]
                // bei einer genau 7 Byte langen Antwort eine IndexOutOfRangeException,
                // gefangen von der pauschalen catch-Klausel in FindServicePortAsync und
                // dort als "Fehler" statt als "kein Modbus" verbucht.
                // [0-1] Transaction Identifier (2 Bytes)
                // [2-3] Protocol Identifier (immer 0x00 0x00 für Modbus TCP)
                // [4-5] Length Field (Länge der nachfolgenden Daten)
                // [6]   Unit Identifier
                // [7]   Function Code
                if (response.Length >= 8)
                {
                    // Protokollkennung überprüfen (muss 0x00 0x00 für Modbus TCP sein)
                    bool isModbusTcp = response[2] == 0x00 && response[3] == 0x00;

                    // Funktioncode prüfen: Gültige Modbus-Funktionscodes liegen zwischen 0x01 und 0x10
                    // Beispiele:
                    // 0x01 - Read Coils
                    // 0x02 - Read Discrete Inputs
                    // 0x03 - Read Holding Registers
                    // 0x04 - Read Input Registers
                    // 0x05 - Write Single Coil
                    // 0x06 - Write Single Register
                    // 0x10 - Write Multiple Registers
                    //
                    // Eine Fehlerantwort (Exception Response) traegt denselben
                    // Funktionscode mit gesetztem oberstem Bit, also 0x81-0x90 -
                    // etwa wenn das angefragte Register auf diesem Geraet nicht
                    // existiert. Das ist trotzdem eine Modbus-Antwort und kein
                    // Nichttreffer: das Geraet hat verstanden und geantwortet,
                    // nur eben mit "nein" statt mit Werten.
                    byte functionCode = response[7];
                    bool validFunctionCode = functionCode is >= 0x01 and <= 0x10 or >= 0x81 and <= 0x90;

                    // Wenn sowohl das Protokoll als auch der Funktionscode stimmen, erkennen wir Modbus TCP
                    if (isModbusTcp && validFunctionCode)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Erst die uebliche Erkennung, danach die Frage nach der Kennung des
        /// Geraets.
        /// <para>
        /// Die Erkennung bleibt unberuehrt - sie entscheidet weiterhin allein
        /// ueber den Befund. Die Antwort, mit der sie das tut, enthaelt aber
        /// nur einen Registerwert und sagt nichts darueber, wer da antwortet.
        /// Wer es verraet, tut es auf Funktionscode 0x2B mit Untertyp 0x0E
        /// ("Read Device Identification"): Hersteller, Produktkennung, Version.
        /// </para>
        /// <para>
        /// Pflicht ist das nicht. Ein Geraet, das den Code nicht kennt,
        /// antwortet mit 0xAB und dem Grund 1 ("unzulaessige Funktion") - das
        /// ist eine gueltige Modbus-Antwort und kein Fehler, nur eben keine
        /// Auskunft. Dann bleibt es bei dem, was ohnehin feststeht.
        /// </para>
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status != PortStatus.IsRunning) return portResult;

            try
            {
                string? info = await ReadDeviceIdentificationAsync(context, address, port, token);
                portResult.PortLog = info ?? "Unit ID 1 answered, device identification not supported.";
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Der Fund steht bereits fest; die Auskunft ist die Zugabe.
            }

            return portResult;
        }

        /// <summary>
        /// Fragt die Grunddaten ab und liest die Objekte aus der Antwort.
        /// <c>null</c>, wenn das Geraet die Funktion nicht kennt.
        /// </summary>
        private static async Task<string?> ReadDeviceIdentificationAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // MBAP-Kopf: Vorgang 2, Protokoll 0, Laenge 5, Einheit 1.
            // Danach: 0x2B Funktionscode, 0x0E Untertyp, 0x01 Grunddaten,
            // 0x00 erstes Objekt.
            byte[] request = [0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00];

            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs);

            await stream.WriteAsync(request, timeout.Token);

            byte[] buffer = new byte[512];
            int read = await stream.ReadAsync(buffer, timeout.Token);
            if (read <= 0) return null;

            return ParseDeviceIdentification(buffer[..read]);
        }

        /// <summary>
        /// Der Aufbau der Antwort: sieben Byte MBAP-Kopf, dann Funktionscode,
        /// Untertyp, Datenklasse, Konformitaet, "folgt noch mehr", naechstes
        /// Objekt, Anzahl - und danach je Objekt Nummer, Laenge, Text.
        /// </summary>
        private static string? ParseDeviceIdentification(byte[] response)
        {
            const int HeaderLength = 7;

            // Zu kurz, oder gar keine Antwort auf diesen Funktionscode.
            if (response.Length < HeaderLength + 2) return null;

            // 0xAB ist 0x2B mit gesetztem obersten Bit: das Geraet kennt die
            // Funktion nicht.
            if (response[HeaderLength] != 0x2B) return null;
            if (response.Length < HeaderLength + 8) return null;

            int count = response[HeaderLength + 6];
            int p = HeaderLength + 7;

            List<string> lines = [];

            for (int i = 0; i < count && p + 1 < response.Length; i++)
            {
                int objectId = response[p];
                int length = response[p + 1];
                p += 2;

                if (p + length > response.Length) break;

                string value = Encoding.ASCII.GetString(response, p, length).Trim();
                p += length;

                if (value.Length == 0) continue;

                lines.Add($"{ObjectName(objectId)}: {value}");
            }

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>Die Objektnummern der Grunddaten, wie sie die Modbus-Spezifikation vergibt.</summary>
        private static string ObjectName(int objectId) => objectId switch
        {
            0x00 => "Vendor",
            0x01 => "Product code",
            0x02 => "Revision",
            0x03 => "Vendor URL",
            0x04 => "Product name",
            0x05 => "Model name",
            0x06 => "Application name",
            _ => $"Object 0x{objectId:X2}"
        };
    }
}
