using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Eine einzelne Sichtung: was ein Verfahren zu einem Zeitpunkt ueber ein
    /// Geraet erfahren hat. Bewusst schmal - ein Verfahren meldet, was es
    /// weiss, und laesst den Rest leer.
    /// <para>
    /// Erst der <see cref="DeviceStore"/> entscheidet, zu welchem Geraet die
    /// Sichtung gehoert. Die Verfahren selbst muessen davon nichts wissen -
    /// genau das macht es moeglich, passive Quellen wie den RA-Mitschnitt und
    /// aktive Scans gleich zu behandeln.
    /// </para>
    /// </summary>
    public sealed class DeviceObservation
    {
        /// <summary>Welches Verfahren die Sichtung gemeldet hat.</summary>
        public required string Source { get; init; }

        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;

        public IpAddressInfo? Address { get; init; }

        public PhysicalAddress? Mac { get; init; }

        /// <summary>
        /// Eine MAC, die das Verfahren zwar nennt, die aber nicht die des
        /// antwortenden Anschlusses sein muss - heute die aus SNMP.
        /// <para>
        /// SNMP meldet die MAC des Verwaltungsanschlusses oder die Basis-MAC
        /// des Geraets. Bei allem mit mehreren Anschluessen - Switch, Router,
        /// Steuerung - ist das eine andere als die, die auf diese Adresse hin
        /// per ARP geantwortet hat. Als harte Kennung genommen, zerlegt sie
        /// ein Geraet in zwei Eintraege, die sich dieselbe Adresse teilen.
        /// </para>
        /// <para>
        /// Sie darf darum eine Zuordnung <em>herstellen</em> und eine leere
        /// MAC fuellen, aber keine Zuordnung <em>verhindern</em> - dieselbe
        /// Regel wie fuer die aus EUI-64 zurueckgerechnete MAC.
        /// </para>
        /// </summary>
        public PhysicalAddress? SoftMac { get; init; }

        /// <summary>DHCPv6-DUID in Hex-Schreibweise.</summary>
        public string? Duid { get; init; }

        public string? HostName { get; init; }
        public string? Domain { get; init; }
        public string? NetBiosName { get; init; }
        public string? Vendor { get; init; }

        /// <summary>Aus welchem Bereich die Sichtung stammt.</summary>
        public string? GroupDescription { get; init; }

        // --- Angaben zur Adresse, soweit das Verfahren sie kennt -------------

        public AddressOrigin Origin { get; init; } = AddressOrigin.Unknown;
        public AddressState State { get; init; } = AddressState.Unknown;
        public DateTimeOffset? ValidUntil { get; init; }
        public DateTimeOffset? PreferredUntil { get; init; }

        /// <summary>Das Ziel hat auf diese Sichtung hin geantwortet.</summary>
        public bool IsResponding { get; init; }

        /// <summary>Freitext des Verfahrens, etwa SNMP- oder mDNS-Angaben.</summary>
        public Dictionary<string, string>? Details { get; init; }

        /// <summary>
        /// Auf welche Adressen der Hostname im DNS zeigt - das Ergebnis des
        /// Vorwaertslookups.
        /// <para>
        /// Ohne DNS ist eine mehrfach vergebene Adresse gar nicht zu sehen:
        /// zwei Geraete, die sich unter demselben Namen eintragen, antworten
        /// jedes fuer sich unauffaellig. Erst der Lookup zeigt, dass hinter
        /// einem Namen mehrere Adressen stehen, und der Rueckwaertslookup, dass
        /// hinter einer Adresse mehrere Namen stehen. Darum sind das eigene
        /// Angaben und kein Freitext in <see cref="Details"/> - nur so laesst
        /// sich danach faerben, filtern und sortieren.
        /// </para>
        /// </summary>
        public List<string>? LookupAddresses { get; init; }

        /// <summary>Weitere Namen zur Adresse, aus dem Rueckwaertslookup.</summary>
        public List<string>? Aliases { get; init; }

        /// <summary>
        /// Rest-TTL der Ping-Antwort. 0 heisst "nicht gemessen" - nur der Ping
        /// fuellt das Feld, alle anderen Verfahren lassen es leer.
        /// </summary>
        public int Ttl { get; init; }

        /// <summary>
        /// Wo das Geraet am Netz haengt, sofern ein Switch danach gefragt
        /// werden konnte. Kommt aus der SNMP-Abfrage, nicht vom Geraet selbst.
        /// </summary>
        public string? SwitchName { get; init; }
        public string? SwitchPort { get; init; }
        public string? Vlan { get; init; }

        /// <summary>Titel der Weboberflaeche und Angaben aus ihrem Zertifikat.</summary>
        public string? WebTitle { get; init; }
        public string? CertificateSubject { get; init; }
        public string? CertificateIssuer { get; init; }
        public DateTimeOffset? CertificateExpires { get; init; }
        public bool? CertificateIsSelfSigned { get; init; }

        /// <summary>
        /// Erkannte Dienste. Der Zustand wird je Adressfamilie gefuehrt - das
        /// meldende Verfahren traegt nur die Seite ein, die es geprueft hat,
        /// die andere bleibt <c>null</c>. Aus dem spaeteren Vergleich beider
        /// Seiten entsteht der Befund "unter IPv4 hinter NAT, unter IPv6 offen".
        /// </summary>
        public List<DeviceServiceResult>? Services { get; init; }

        public override string ToString() =>
            $"{Source}: {Address?.Canonical ?? HostName ?? Mac?.ToString() ?? "?"}";
    }
}
