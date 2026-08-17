namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Microsoft Remote Desktop. Gefragt wird mit einer X.224-Verbindungs-
    /// anfrage; die Antwort ist ein TPKT-Paket, das im COTP-Teil den Code
    /// "Connection Confirm" traegt.
    /// </summary>
    public sealed class RdpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RDP;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [3389];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? RDP: Antwort auf die X.224-Verbindungsanfrage ist ein TPKT-Paket
            // (0x03 0x00 ...), das im COTP-Teil den Code 0xD0 (Connection Confirm)
            // traegt.
            if (service == ServiceType.RDP)
            {
                if (response.Length >= 6 && response[0] == 0x03 && response[1] == 0x00 && response[5] == 0xD0)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Welche Sicherheitsschicht der Server fuer die Anmeldung waehlt.
        /// <para>
        /// Das Erkennungspaket fragt bereits nach TLS und CredSSP - die letzten
        /// vier Byte der Anfrage sind genau diese beiden Wuensche. Was der
        /// Server daraufhin waehlt, steht in seiner Antwort und ist die
        /// eigentliche Auskunft: <c>CredSSP</c> heisst, dass sich ein Betrachter
        /// ausweisen muss, <em>bevor</em> ein Anmeldebildschirm erscheint. Fehlt
        /// es, nimmt der Server jede Verbindung bis zum Anmeldebildschirm an -
        /// die Lage, die Wuermer wie BlueKeep gebraucht haben.
        /// </para>
        /// <para>
        /// Reines Mitlesen der Antwort auf das ohnehin gesendete Paket; kein
        /// Anmeldeversuch und keine zweite Verbindung.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            // Der Aushandlungsteil beginnt hinter TPKT-Kopf (4) und X.224-Bestaetigung
            // (7). Fehlt er, hat der Server ohne Aushandlung bestaetigt - das
            // ist selbst die Auskunft, denn dann bleibt es beim alten Verfahren.
            const int negotiation = 11;

            if (response.Length < negotiation + 1)
            {
                return "Security: Standard RDP (no NLA)";
            }

            byte type = response[negotiation];

            // 0x02 - der Server nennt das gewaehlte Verfahren in den vier Byte
            // ab Position 15, little-endian.
            if (type == 0x02 && response.Length >= negotiation + 8)
            {
                int selected = response[negotiation + 4]
                    | response[negotiation + 5] << 8
                    | response[negotiation + 6] << 16
                    | response[negotiation + 7] << 24;

                return $"Security: {ProtocolName(selected)}";
            }

            // 0x03 - er lehnt das Gewuenschte ab und nennt den Grund. Auch das
            // ist eine Aussage ueber seine Einstellung, keine Stoerung.
            if (type == 0x03 && response.Length >= negotiation + 8)
            {
                return $"Security: {FailureReason(response[negotiation + 4])}";
            }

            return "Security: Standard RDP (no NLA)";
        }

        /// <summary>Die Verfahren aus der RDP-Festlegung; sie sind Bitwerte.</summary>
        private static string ProtocolName(int selected) => selected switch
        {
            0x00 => "Standard RDP (no NLA)",
            0x01 => "TLS, no NLA",
            0x02 => "CredSSP (NLA)",
            0x08 => "RDSTLS",
            0x10 => "CredSSP with early user authentication",
            _ => $"protocol {selected}"
        };

        /// <summary>
        /// Die Ablehnungsgruende. Zwei davon sind keine schlechte Nachricht:
        /// wer TLS oder NLA <em>verlangt</em>, ist strenger eingestellt als der,
        /// der alles annimmt.
        /// </summary>
        private static string FailureReason(byte code) => code switch
        {
            0x01 => "TLS required by server",
            0x02 => "TLS not allowed by server",
            0x03 => "no server certificate installed",
            0x05 => "CredSSP (NLA) required by server",
            0x06 => "TLS with user authentication required",
            _ => $"negotiation refused (code {code})"
        };
    }
}
