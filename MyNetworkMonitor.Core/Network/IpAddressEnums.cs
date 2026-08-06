namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Adressfamilie in der Schreibweise der Anwendung. Bewusst nicht
    /// <see cref="System.Net.Sockets.AddressFamily"/>, damit Modell und
    /// Oberflaeche nicht von Socket-Typen abhaengen.
    /// </summary>
    public enum IpFamily
    {
        IPv4,
        IPv6
    }

    /// <summary>
    /// Gueltigkeitsbereich einer Adresse. Bestimmt, was mit ihr ueberhaupt
    /// moeglich ist: eine Link-Local-Adresse ist ohne Zone-ID nicht
    /// ansprechbar, eine globale Adresse ist ohne NAT direkt erreichbar.
    /// </summary>
    public enum IpAddressScope
    {
        Unknown,

        /// <summary>::1 bzw. 127.0.0.0/8</summary>
        Loopback,

        /// <summary>:: bzw. 0.0.0.0 - keine Adresse.</summary>
        Unspecified,

        /// <summary>fe80::/10 bzw. 169.254.0.0/16. Nur im selben Segment gueltig.</summary>
        LinkLocal,

        /// <summary>fc00::/7 (ULA) bzw. RFC-1918-Bereiche. Lokal gueltig, nicht im Internet geroutet.</summary>
        UniqueLocal,

        /// <summary>2000::/3 bzw. oeffentliche IPv4. Weltweit geroutet.</summary>
        Global,

        /// <summary>ff00::/8 bzw. 224.0.0.0/4</summary>
        Multicast,

        /// <summary>255.255.255.255 - nur IPv4.</summary>
        Broadcast
    }

    /// <summary>
    /// Sonderformen, die einer Adresse zusaetzlich zum <see cref="IpAddressScope"/>
    /// anzusehen sind. Mehrere davon tragen eine eingebettete IPv4-Adresse, die
    /// sich auslesen und mit der IPv4-Sicht abgleichen laesst.
    /// </summary>
    public enum IpAddressSpecial
    {
        None,

        /// <summary>::ffff:a.b.c.d - eine IPv4-Adresse in IPv6-Schreibweise.</summary>
        IPv4Mapped,

        /// <summary>::a.b.c.d - laengst abgekuendigt, taucht aber noch auf.</summary>
        IPv4Compatible,

        /// <summary>2001:0::/32 - Tunnel durch NAT hindurch.</summary>
        Teredo,

        /// <summary>2002::/16 - IPv6 ueber IPv4 getunnelt.</summary>
        SixToFour,

        /// <summary>Interface-Identifier 0000:5efe oder 0200:5efe mit angehaengter IPv4.</summary>
        Isatap,

        /// <summary>64:ff9b::/96 - well-known Praefix fuer NAT64/DNS64.</summary>
        Nat64WellKnown,

        /// <summary>2001:db8::/32 - nur fuer Dokumentation, darf real nicht vorkommen.</summary>
        Documentation,

        /// <summary>2001:2::/48 - fuer Messungen reserviert.</summary>
        Benchmarking,

        /// <summary>ff02::1:ffXX:XXXX - verraet die unteren 24 Bit eines Interface-Identifiers.</summary>
        SolicitedNodeMulticast,

        /// <summary>fc00::/8 - zentral zu vergeben, bislang nie zugeteilt. Deutet auf Fehlkonfiguration.</summary>
        UnassignedUniqueLocal
    }

    /// <summary>
    /// Herkunft der unteren 64 Bit einer IPv6-Adresse, soweit sie sich aus den
    /// Bits selbst ableiten laesst.
    /// <para>
    /// Wichtig: <see cref="Random"/> umfasst sowohl Privacy Extensions
    /// (RFC 4941, wechselt taeglich) als auch stabile opake Identifier
    /// (RFC 7217, bleibt pro Praefix gleich). Beide sind pseudozufaellig und
    /// <b>aus der Adresse allein nicht unterscheidbar</b>. Die Unterscheidung
    /// gelingt nur ueber die Zeit (wechselt sie?) oder ueber die Angabe des
    /// Betriebssystems (SuffixOrigin). Der Analysator behauptet hier bewusst
    /// nicht mehr, als er wissen kann.
    /// </para>
    /// </summary>
    public enum InterfaceIdKind
    {
        Unknown,

        /// <summary>Nur IPv4 - kein Interface-Identifier vorhanden.</summary>
        NotApplicable,

        /// <summary>
        /// Aus einer MAC-Adresse gebildet (ff:fe in der Mitte, u/l-Bit gekippt).
        /// Die MAC laesst sich zurueckrechnen - siehe <see cref="IpAddressInfo.DerivedMac"/>.
        /// </summary>
        Eui64,

        /// <summary>Sehr kleiner Wert wie ::1 oder ::20. In aller Regel von Hand vergeben.</summary>
        LowByte,

        /// <summary>Pseudozufaellig. Privacy Extension oder stabiler opaker Identifier - siehe Hinweis am Enum.</summary>
        Random,

        /// <summary>Traegt eine eingebettete IPv4-Adresse (6to4, ISATAP, NAT64, Teredo).</summary>
        Embedded
    }

    /// <summary>
    /// Wie eine Adresse an das Interface gekommen ist. Wird nicht aus den Bits
    /// abgeleitet, sondern vom Betriebssystem gemeldet (unter Windows
    /// PrefixOrigin/SuffixOrigin, unter Linux die Flags aus <c>ip -6 addr</c>).
    /// </summary>
    public enum AddressOrigin
    {
        Unknown,

        /// <summary>Aus einem Router Advertisement gebildet.</summary>
        Slaac,

        /// <summary>Von einem DHCP- bzw. DHCPv6-Server zugeteilt.</summary>
        Dhcp,

        /// <summary>Von Hand eingetragen.</summary>
        Manual,

        /// <summary>Fest vorgegeben, etwa Loopback.</summary>
        WellKnown,

        /// <summary>Aus der Adresse der Schicht 2 gebildet.</summary>
        LinkLayer,

        /// <summary>Zufaellig erzeugt.</summary>
        Random
    }

    /// <summary>
    /// Zustand einer Adresse aus Sicht der Duplicate Address Detection und der
    /// Lebensdauern. <see cref="Duplicate"/> ist ein Befund und gehoert gemeldet.
    /// </summary>
    public enum AddressState
    {
        Unknown,

        /// <summary>Pruefung laeuft noch, Adresse darf nicht benutzt werden.</summary>
        Tentative,

        /// <summary>Gueltig und bevorzugt fuer neue Verbindungen.</summary>
        Preferred,

        /// <summary>Noch gueltig, aber nicht mehr fuer neue Verbindungen zu verwenden.</summary>
        Deprecated,

        /// <summary>Lebensdauer abgelaufen.</summary>
        Invalid,

        /// <summary>Die Adresse ist im Segment bereits vergeben.</summary>
        Duplicate
    }
}
