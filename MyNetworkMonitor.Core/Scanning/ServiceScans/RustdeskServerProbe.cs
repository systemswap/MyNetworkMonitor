namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// RustDesk-Server. Ein Server belegt einen Block von fuenf Ports um
    /// seinen Basisport: Basis-1 NAT-Test, Basis ID und Heartbeat, Basis+1
    /// Relay, Basis+2 und +3 WebSocket.
    /// <para>
    /// Aufgefuehrt sind nur die beiden, die den NAT-Test beantworten - nur sie
    /// koennen die Pruefung bestehen. Der Relay-Port schweigt auf alles, die
    /// WebSocket-Ports sprechen HTTP.
    /// </para>
    /// <para>
    /// 5990/5991 sind keine Vorgabe des Herstellers, sondern ein abweichender
    /// Basisport, wie er bei einem selbst betriebenen Server vorkommt.
    /// Ungefaehrlich, weil die Antwort echt geprueft wird - ein fremder Dienst
    /// auf diesen Ports geht damit nicht als RustDesk durch. Frueher stand
    /// hier 5900, derselbe Port wie VNC, und weil damals jede Antwort als
    /// Treffer galt, wurde an jedem VNC-Rechner zusaetzlich ein
    /// RustDesk-Server gemeldet.
    /// </para>
    /// </summary>
    public sealed class RustdeskServerProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RustdeskServer;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5990, 5991, 21115, 21116];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x14, 0xa2, 0x01, 0x02, 0x08, 0x03 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? RustDesk-Server (hbbs, Ports 21115-21117 bzw. eigener Port)
            //
            // Auf das Hello aus GetDetectionPacket - der NAT-Test-Anfrage -
            // antwortet der Server mit dem Quellport, den er von uns sieht:
            //
            //   1c aa 01 04 08 <Port als Varint>
            //
            // An einem echten Server ueber vier Verbindungen gemessen: der
            // zurueckgegebene Wert war jedes Mal genau der TCP-Quellport der
            // eigenen Verbindung. Das ist mehr als ein Muster - die Antwort haengt
            // an der Verbindung und laesst sich nicht zufaellig von einem anderen
            // Dienst nachbilden.
            //
            // Die Laenge ist nicht fest: ein Quellport unter 16384 passt in zwei
            // Varint-Byte statt drei. Darum wird das Laengenfeld gegen die
            // tatsaechliche Laenge geprueft, nicht auf 8 Byte bestanden.
            if (service == ServiceType.RustdeskServer)
            {
                serviceMatched = response.Length is >= 7 and <= 9
                    && response[0] == 0x1C
                    && response[1] == 0xAA && response[2] == 0x01   // Feld 21, laengenkodiert
                    && response[3] == response.Length - 4           // innere Laenge passt zum Rest
                    && response[4] == 0x08                          // Feld 1, Varint: der Port
                    && TryReadVarint(response, 5, out int publicPort)
                    && publicPort is > 0 and <= 65535;
            }

            return serviceMatched;
        }
    }
}
