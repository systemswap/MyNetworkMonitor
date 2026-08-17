namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Der Name, unter dem ein Dienst in der Oberflaeche steht.
    /// <para>
    /// Bisher stand dort <c>ServiceType.ToString()</c>, also der Bezeichner aus
    /// dem Quelltext. Der taugt als Schluessel, aber nicht immer als Auskunft:
    /// "S7" sagt nur etwas, wer das Protokoll ohnehin kennt.
    /// </para>
    /// <para>
    /// Der Umweg ueber diese Tabelle statt einer Umbenennung im Enum ist
    /// Absicht - der Enum-Name steht in gespeicherten Bestaenden und in den
    /// Einstellungen der Verfahren; ihn zu aendern wuerde beide entwerten.
    /// </para>
    /// </summary>
    public static class ServiceNames
    {
        public static string Of(ServiceType service) => service switch
        {
            ServiceType.S7 => "S7 PLC (SPS)",
            _ => service.ToString()
        };

        /// <summary>
        /// Der Anzeigename zu einem gespeicherten Dienstnamen. Laesst sich der
        /// Text als <see cref="ServiceType"/> lesen, gilt dessen Anzeigename;
        /// sonst bleibt der Text stehen - etwa fuer Sammelzeilen wie "TCP Ports".
        /// </summary>
        public static string DisplayFor(string rawName) =>
            Enum.TryParse(rawName, out ServiceType service) ? Of(service) : rawName;

        /// <summary>
        /// Die Dienste, deren Sonde mehr zurueckbringt als "laeuft", und die
        /// Ueberschrift, unter der es in den Details steht. Wer hier fehlt,
        /// dessen Protokoll bleibt in der Dienstzeile und wandert nicht in die
        /// Detailansicht - dort stuende sonst bei jedem zweiten Dienst die
        /// Notiz "Antwort passt zum erwarteten Protokoll".
        /// </summary>
        public static readonly (ServiceType Service, string Label)[] WithDeviceInfo =
        [
            (ServiceType.BacNet, "BACnet device"),
            (ServiceType.ModBus, "Modbus device"),
            (ServiceType.OPCUA,  "OPC UA server"),
            (ServiceType.S7,     "S7 PLC"),
            (ServiceType.Wago,   "WAGO device"),

            // Dienste, die sich beim Verbindungsaufbau selbst vorstellen. Sie
            // sagen nicht so viel ueber sich wie eine Steuerung, aber Software,
            // Fassung und Anmeldeverfahren stehen vor jeder Anmeldung fest -
            // und gerade das Anmeldeverfahren ist bei VNC und RDP der Befund,
            // wegen dessen man ueberhaupt sucht.
            (ServiceType.FTP,          "FTP server"),
            (ServiceType.SSH,          "SSH server"),
            (ServiceType.RDP,          "Remote Desktop"),
            (ServiceType.UltraVNC,     "VNC server"),
            (ServiceType.MySQL,        "MySQL server"),
            (ServiceType.MariaDB,      "MariaDB server"),
            (ServiceType.MSSQLServer,  "SQL Server"),
            (ServiceType.PostgreSQL,   "PostgreSQL server"),
            (ServiceType.OracleDB,     "Oracle listener"),
            (ServiceType.MongoDB,      "MongoDB server"),
            (ServiceType.InfluxDB2,    "InfluxDB server")
        ];

        /// <summary>Die Ueberschrift fuer diesen Dienst, oder <c>null</c>, wenn er keine Auskunft liefert.</summary>
        public static string? InfoLabelOf(ServiceType service)
        {
            foreach ((ServiceType candidate, string label) in WithDeviceInfo)
            {
                if (candidate == service) return label;
            }

            return null;
        }
    }
}
