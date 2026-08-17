using System.Net.Sockets;
using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// VNC. Ein Server gruesst beim Verbinden von sich aus mit seiner
    /// Protokollkennung ("RFB 003.008"); das Hello-Paket ist die
    /// Gegenvorstellung.
    /// <para>
    /// Die vier Ports sind die Anzeigen 0 bis 3 - ein Rechner mit mehreren
    /// Sitzungen belegt sie der Reihe nach.
    /// </para>
    /// </summary>
    public sealed class UltraVncProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.UltraVNC;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5900, 5901, 5902, 5903];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? UltraVNC-Erkennung        
            if (service == ServiceType.UltraVNC)
            {
                //UlraVNC Header RFB als hex
                byte[] ultraVncHeader = { 0x52, 0x46, 0x42 };

                if (response.Take(ultraVncHeader.Length).SequenceEqual(ultraVncHeader))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Die Protokollfassung aus der Begruessung. Sie steht in einem festen
        /// Format da - "RFB 003.008" -, und die letzte Stelle sagt, welchen
        /// Handshake der Server erwartet.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));

            return banner.Length >= 11 ? $"Protocol: {banner[..11]}" : null;
        }

        /// <summary>
        /// Fragt ab, womit sich ein Betrachter anmelden muesste.
        /// <para>
        /// Der RFB-Handshake sieht das ungefragt vor: nachdem beide Seiten ihre
        /// Fassung genannt haben, schickt der Server die Liste seiner
        /// Anmeldeverfahren - noch bevor irgendein Passwort faellig waere. Steht
        /// dort <c>None</c>, kommt jeder ohne Passwort auf diesen Bildschirm,
        /// und genau das ist der Grund, diese Frage zu stellen.
        /// </para>
        /// <para>
        /// Das Erkennungspaket bleibt unberuehrt. Es traegt die ersten sieben
        /// Zeichen der Fassungszeile; der Server wartet danach noch auf die
        /// fuenf, die zu den vorgeschriebenen zwoelf fehlen. Genau die werden
        /// hier nachgereicht - keine Aenderung am Hello, sondern dessen
        /// Fortsetzung.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(firstResponse));
            if (banner.Length < 11) return null;

            // Die eigene Fassung darf die des Servers nicht ueberschreiten -
            // sonst lehnt er ab. Uebernommen wird darum seine eigene Angabe.
            byte[] rest = Encoding.ASCII.GetBytes(banner[7..11] + "\n");
            await stream.WriteAsync(rest, token);

            byte[] buffer = new byte[256];
            int read = await stream.ReadAsync(buffer, token);
            if (read < 1) return null;

            // Ab 3.7: ein Zaehler, dann je ein Byte je Verfahren. Eine Null
            // heisst nicht "keines", sondern dass der Server die Verbindung
            // ablehnt und den Grund als Text nachschiebt.
            int count = buffer[0];

            if (count == 0)
            {
                string reason = Printable(Encoding.ASCII.GetString(buffer, 1, read - 1), 120);
                return reason.Length > 0 ? $"Rejected: {reason}" : null;
            }

            List<string> methods = [];
            bool openAccess = false;

            for (int i = 1; i < read && i <= count; i++)
            {
                if (buffer[i] == 1) openAccess = true;

                string name = SecurityTypeName(buffer[i]);
                if (!methods.Contains(name)) methods.Add(name);
            }

            if (methods.Count == 0) return null;

            List<string> lines = [$"Authentication: {string.Join(", ", methods)}"];

            // Als eigene Zeile und im Klartext: in einer Aufzaehlung von
            // Verfahren geht "None" unter, und es ist der Befund, auf den es
            // hier ankommt.
            if (openAccess) lines.Add("Warning: accepts connections without a password");

            return string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Die Verfahrensnummern aus der RFB-Festlegung, dazu die verbreiteten
        /// herstellereigenen. Unbekannte werden mit ihrer Nummer genannt statt
        /// verschwiegen - sie sagt einem Kundigen mehr als "unbekannt".
        /// </summary>
        private static string SecurityTypeName(byte type) => type switch
        {
            1 => "None",
            2 => "VNC password",
            5 => "RA2",
            6 => "RA2ne",
            16 => "Tight",
            17 => "Ultra",
            18 => "TLS",
            19 => "VeNCrypt",
            20 => "SASL",
            30 => "Apple Remote Desktop",

            // Die Nummern jenseits von 112 sind UltraVNC-eigen und stehen in
            // keiner allgemeinen Festlegung. MS-Logon nimmt die Zugangsdaten
            // aus der Windows-Anmeldung - hier laeuft also kein eigenes
            // VNC-Passwort, sondern ein Konto der Domaene.
            113 => "MS-Logon II",
            114 => "MS-Logon I",
            _ => $"Type {type}"
        };
    }
}
