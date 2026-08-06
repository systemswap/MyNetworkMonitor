using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Eine ausgewertete IP-Adresse. Anders als unter IPv4 ist eine IPv6-Adresse
    /// selbst schon ein Datensatz: Praefix, Gueltigkeitsbereich, Herkunft des
    /// Interface-Identifiers und teilweise sogar die MAC oder eine eingebettete
    /// IPv4-Adresse lassen sich allein aus den Bits ableiten.
    /// <para>
    /// Erzeugt wird der Datensatz ueber <see cref="IpAddressAnalyzer.Analyze"/>.
    /// Alles, was <b>nicht</b> aus der Adresse selbst folgt - Lebensdauern,
    /// Zustand, Herkunft laut Betriebssystem - sitzt bewusst nicht hier, sondern
    /// am Geraet, weil es von der Beobachtung abhaengt und nicht von der Adresse.
    /// </para>
    /// </summary>
    public sealed class IpAddressInfo
    {
        public required IPAddress Address { get; init; }

        public required IpFamily Family { get; init; }

        public required IpAddressScope Scope { get; init; }

        public IpAddressSpecial Special { get; init; } = IpAddressSpecial.None;

        public InterfaceIdKind InterfaceIdKind { get; init; } = InterfaceIdKind.Unknown;

        /// <summary>
        /// Zone- bzw. Scope-ID einer Link-Local-Adresse (der Teil hinter dem %).
        /// Ohne sie ist eine fe80-Adresse nicht ansprechbar, darum muss sie
        /// ueberall dort mitgefuehrt werden, wo Adressen als Text durchgereicht
        /// werden. <c>null</c>, wenn keine angegeben war.
        /// </summary>
        public long? ZoneId { get; init; }

        /// <summary>
        /// Die aus einem EUI-64-Interface-Identifier zurueckgerechnete MAC.
        /// Nur gesetzt, wenn <see cref="InterfaceIdKind"/> gleich
        /// <see cref="InterfaceIdKind.Eui64"/> ist. Damit ist der Hersteller
        /// auch dann bestimmbar, wenn das Geraet nicht im selben Segment liegt.
        /// </summary>
        public PhysicalAddress? DerivedMac { get; init; }

        /// <summary>
        /// Die in der Adresse enthaltene IPv4-Adresse bei 6to4, ISATAP, NAT64,
        /// Teredo oder IPv4-mapped. Erlaubt den Abgleich mit der IPv4-Sicht.
        /// </summary>
        public IPAddress? EmbeddedIPv4 { get; init; }

        /// <summary>
        /// Kanonische Schreibweise nach RFC 5952 (klein, laengste Nullfolge
        /// zusammengefasst), mit angehaengter Zone, falls vorhanden. Diese Form
        /// ist zu speichern und zu vergleichen - nicht die Eingabe des Nutzers,
        /// denn dieselbe Adresse laesst sich auf viele Arten schreiben.
        /// </summary>
        public required string Canonical { get; init; }

        /// <summary>
        /// 16 Byte in Netzwerkreihenfolge, fuer stabile Sortierung. IPv4 wird
        /// dabei als IPv4-mapped eingeordnet, damit v4 und v6 in einer Spalte
        /// nebeneinander sortierbar bleiben.
        /// </summary>
        public required byte[] SortKey { get; init; }

        /// <summary>
        /// Weltweit erreichbar - und damit ohne NAT direkt aus dem Internet
        /// ansprechbar. Grundlage fuer den Befund "Port global offen".
        /// </summary>
        public bool IsGloballyRoutable => Scope == IpAddressScope.Global;

        /// <summary>
        /// Die Adresse taugt nicht als dauerhafte Kennung eines Geraetes -
        /// entweder weil sie sich regelmaessig aendert oder weil sie nur im
        /// Segment gilt. Verhindert, dass ein Geraet mit Privacy Extensions
        /// als mehrere Geraete gezaehlt wird.
        /// </summary>
        public bool IsUnstableIdentity =>
            InterfaceIdKind == InterfaceIdKind.Random || Scope == IpAddressScope.LinkLocal;

        public override string ToString() => Canonical;
    }
}
