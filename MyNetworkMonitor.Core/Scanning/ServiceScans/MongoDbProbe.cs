using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>MongoDB. Gefragt wird mit einer Wire-Protocol-Anfrage.</summary>
    public sealed class MongoDbProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.MongoDB;
        public override string Group => ServiceGroups.NoSqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [27017];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
           {
                0x4C, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0x01, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6D, 0x61,
                0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x4F,
                0x6B, 0x00, 0x01, 0x03, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x00, 0xE2, 0x00, 0x00, 0x00, 0x03,
                0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x1F, 0x00, 0x00, 0x00,
                0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x4D, 0x6F, 0x6E, 0x67, 0x6F, 0x44,
                0x42, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x61, 0x73, 0x73, 0x00, 0x00, 0x03, 0x64, 0x72, 0x69, 0x76,
                0x65, 0x72, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x6E, 0x6F, 0x64, 0x65, 0x6A, 0x73, 0x00, 0x02, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
                0x00, 0x07, 0x00, 0x00, 0x00, 0x36, 0x2E, 0x31, 0x32, 0x2E, 0x30, 0x00, 0x00, 0x02, 0x70, 0x6C,
                0x61, 0x74, 0x66, 0x6F, 0x72, 0x6D, 0x00, 0x15, 0x00, 0x00, 0x00, 0x4E, 0x6F, 0x64, 0x65, 0x2E,
                0x6A, 0x73, 0x20, 0x76, 0x32, 0x30, 0x2E, 0x31, 0x38, 0x2E, 0x31, 0x2C, 0x20, 0x4C, 0x45, 0x00,
                0x03, 0x6F, 0x73, 0x00, 0x58, 0x00, 0x00, 0x00, 0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x06, 0x00,
                0x00, 0x00, 0x77, 0x69, 0x6E, 0x33, 0x32, 0x00, 0x02, 0x61, 0x72, 0x63, 0x68, 0x69, 0x74, 0x65,
                0x63, 0x74, 0x75, 0x72, 0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x36, 0x34, 0x00, 0x02, 0x76,
                0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x31, 0x30, 0x2E, 0x30, 0x2E,
                0x31, 0x39, 0x30, 0x34, 0x34, 0x00, 0x02, 0x74, 0x79, 0x70, 0x65, 0x00, 0x0B, 0x00, 0x00, 0x00,
                0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5F, 0x4E, 0x54, 0x00, 0x00, 0x00, 0x04, 0x63, 0x6F,
                0x6D, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x11, 0x00, 0x00, 0x00, 0x02, 0x30,
                0x00, 0x05, 0x00, 0x00, 0x00, 0x6E, 0x6F, 0x6E, 0x65, 0x00, 0x00, 0x00
           };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            if (service == ServiceType.MongoDB)
            {
                // Typischer MongoDB-Header in der Antwort
                byte[] bjsonHeader = { 0x49, 0x01, 0x00, 0x00 };  // BJSON format beginnt so

                bool bjsonHeaderMatched = response.Take(4).SequenceEqual(bjsonHeader);
                bool str_ContainsHelloOK = str_serviceResponse.ToLower().Contains("hellook");
                bool str_Contains_topologyVersion = str_serviceResponse.ToLower().Contains("topologyversion");

                if (bjsonHeaderMatched && str_ContainsHelloOK && str_Contains_topologyVersion)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Wertet die Antwort auf <c>isMaster</c> aus - die Frage, die das
        /// Erkennungspaket ohnehin stellt und die jeder Server vor jeder
        /// Anmeldung beantwortet, weil ein Client daraus erst lernt, wohin er
        /// schreiben darf.
        /// <para>
        /// Eine Fassungsnummer steht nicht darin; <c>buildInfo</c> traegt sie,
        /// verlangt aber je nach Einstellung eine Anmeldung. Was hier steht, ist
        /// <c>maxWireVersion</c> - die Nummer des Protokollstandes, und die ist
        /// fest an die Serverreihe gekoppelt.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            List<string> lines = [];

            if (TryReadInt32Field(response, "maxWireVersion", out int wire))
            {
                string release = ReleaseOf(wire);

                lines.Add(release.Length > 0
                    ? $"Version: {release} (wire protocol {wire})"
                    : $"Wire protocol: {wire}");
            }

            // Ein Satz mit "isdbgrid" kennzeichnet den Verteiler vor einem
            // verteilten Bestand, keinen Server mit eigenen Daten.
            string role = ReadStringField(response, "msg") == "isdbgrid"
                ? "mongos router"
                : RoleOf(response);

            if (role.Length > 0) lines.Add($"Role: {role}");

            string replicaSet = ReadStringField(response, "setName");
            if (replicaSet.Length > 0) lines.Add($"Replica set: {replicaSet}");

            // Wie der Server sich selbst nennt. Steht oft ein Name drin, den
            // das DNS nicht kennt - der interne Name innerhalb des Verbunds.
            string me = ReadStringField(response, "me");
            if (me.Length > 0) lines.Add($"Reports itself as: {me}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// Die Rolle im Verbund. Der Name des Feldes wechselte mit Fassung 5.0
        /// von <c>ismaster</c> auf <c>isWritablePrimary</c>; beide werden
        /// gelesen, weil beide Fassungen im Feld stehen.
        /// </summary>
        private static string RoleOf(byte[] response)
        {
            bool writable =
                ReadBoolField(response, "isWritablePrimary") == true ||
                ReadBoolField(response, "ismaster") == true;

            if (writable) return "primary";

            return ReadBoolField(response, "secondary") == true ? "secondary" : string.Empty;
        }

        /// <summary>
        /// Die Serverreihe zu einem Protokollstand. Die Zuordnung ist von
        /// MongoDB festgelegt und aendert sich rueckwirkend nicht - ein Server
        /// mit Stand 21 ist ein 7.0er. Unbekannt heisst hier "neuer als das,
        /// was zur Bauzeit bekannt war"; dann steht nur die Nummer da.
        /// </summary>
        private static string ReleaseOf(int wireVersion) => wireVersion switch
        {
            6 => "3.6",
            7 => "4.0",
            8 => "4.2",
            9 => "4.4",
            13 => "5.0",
            14 => "5.1",
            17 => "6.0",
            21 => "7.0",
            25 => "8.0",
            _ => string.Empty
        };

        /// <summary>
        /// Sucht ein Feld in der BSON-Antwort und liefert die Stelle, an der
        /// sein Wert beginnt, sowie den Typ davor. BSON reiht Felder als
        /// <c>&lt;Typ&gt;&lt;Name&gt;\0&lt;Wert&gt;</c>; gesucht wird der Name
        /// samt der Null dahinter, damit "me" nicht in "message" trifft.
        /// </summary>
        private static bool TryFindField(byte[] data, string name, out int valueStart, out byte type)
        {
            valueStart = 0;
            type = 0;

            byte[] pattern = Encoding.ASCII.GetBytes(name + "\0");

            for (int i = 1; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;

                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j]) { match = false; break; }
                }

                if (!match) continue;

                // Das Byte vor dem Namen ist die Typkennung des Feldes.
                type = data[i - 1];
                valueStart = i + pattern.Length;

                return valueStart < data.Length;
            }

            return false;
        }

        /// <summary>Ein 32-Bit-Feld (Typ 0x10), little-endian.</summary>
        private static bool TryReadInt32Field(byte[] data, string name, out int value)
        {
            value = 0;

            if (!TryFindField(data, name, out int start, out byte type)) return false;
            if (type != 0x10 || start + 4 > data.Length) return false;

            value = data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24;

            return true;
        }

        /// <summary>Ein Wahrheitsfeld (Typ 0x08). <c>null</c>, wenn es fehlt.</summary>
        private static bool? ReadBoolField(byte[] data, string name)
        {
            if (!TryFindField(data, name, out int start, out byte type)) return null;
            if (type != 0x08 || start >= data.Length) return null;

            return data[start] != 0;
        }

        /// <summary>
        /// Ein Zeichenkettenfeld (Typ 0x02). Aufbau: vier Byte Laenge
        /// einschliesslich der abschliessenden Null, dann der Text.
        /// </summary>
        private static string ReadStringField(byte[] data, string name)
        {
            if (!TryFindField(data, name, out int start, out byte type)) return string.Empty;
            if (type != 0x02 || start + 4 > data.Length) return string.Empty;

            int length = data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24;

            // Die Laenge zaehlt die Null mit; unglaubwuerdige Werte werden
            // verworfen, statt blind in den Puffer zu greifen.
            if (length is < 2 or > 256) return string.Empty;
            if (start + 4 + length > data.Length) return string.Empty;

            return Printable(Encoding.UTF8.GetString(data, start + 4, length - 1), 80);
        }
    }
}
