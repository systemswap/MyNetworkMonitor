using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Wie weit IPv6 auf einem Adapter tatsaechlich nutzbar ist.
    /// <para>
    /// In vielen Netzen ist IPv6 abgeschaltet, nur halb eingerichtet oder es
    /// fehlt schlicht der Router, der ein Praefix ankuendigt. Die Anwendung
    /// muss das erkennen, <b>bevor</b> sie IPv6-Verfahren startet - sonst
    /// laufen sie ohne Ergebnis in ihre Zeitlimits und der Nutzer sieht leere
    /// Spalten ohne Erklaerung.
    /// </para>
    /// </summary>
    public enum Ipv6Availability
    {
        /// <summary>Noch nicht geprueft.</summary>
        Unknown,

        /// <summary>Das Betriebssystem selbst kann kein IPv6.</summary>
        NotSupportedByOperatingSystem,

        /// <summary>Der Adapter hat IPv6 nicht gebunden - im Adapter abgeschaltet.</summary>
        DisabledOnAdapter,

        /// <summary>
        /// IPv6 ist gebunden, aber es gibt keine einzige IPv6-Adresse.
        /// Ungewoehnlich, kommt bei frisch gestarteten oder gestoerten
        /// Adaptern vor.
        /// </summary>
        NoAddress,

        /// <summary>
        /// Nur eine Link-Local-Adresse vorhanden. Der Adapter kann IPv6, aber
        /// im Netz kuendigt kein Router ein Praefix an. Das Segment selbst
        /// laesst sich trotzdem vollstaendig untersuchen - Neighbor Discovery,
        /// Multicast und MLD arbeiten alle ueber Link-Local.
        /// </summary>
        LinkLocalOnly,

        /// <summary>
        /// Zusaetzlich eine ULA, aber keine globale Adresse. Internes IPv6
        /// ohne Anbindung nach aussen.
        /// </summary>
        UniqueLocalOnly,

        /// <summary>Globale Adresse vorhanden - IPv6 vollstaendig nutzbar.</summary>
        Global
    }

    /// <summary>
    /// Ergebnis der Verfuegbarkeitspruefung samt Begruendung. Die Begruendung
    /// ist fuer die Oberflaeche gedacht: sie steht dort, wo sonst die
    /// IPv6-Ergebnisse staenden.
    /// </summary>
    public sealed class Ipv6Readiness
    {
        public required Ipv6Availability Availability { get; init; }

        /// <summary>Kurzer Satz fuer die Oberflaeche, warum es so ist, wie es ist.</summary>
        public required string Reason { get; init; }

        /// <summary>
        /// IPv6-Verfahren im Segment sind sinnvoll: Neighbor Cache, Multicast
        /// an ff02::1, Router Advertisements und MLD brauchen nur Link-Local.
        /// </summary>
        public bool CanScanLocalSegment =>
            Availability is Ipv6Availability.LinkLocalOnly
                         or Ipv6Availability.UniqueLocalOnly
                         or Ipv6Availability.Global;

        /// <summary>
        /// Ziele ausserhalb des eigenen Segments sind ueber IPv6 erreichbar.
        /// Ohne globale oder lokal eindeutige Adresse ist das nicht der Fall.
        /// </summary>
        public bool CanScanRoutedTargets =>
            Availability is Ipv6Availability.UniqueLocalOnly or Ipv6Availability.Global;

        /// <summary>
        /// Die Pruefung "ist dieser Port global erreichbar" ist nur mit einer
        /// globalen Adresse aussagekraeftig.
        /// </summary>
        public bool CanAssessGlobalExposure => Availability == Ipv6Availability.Global;

        /// <summary>
        /// IPv6-Spalten und -Ansichten ausblenden statt leer zeigen. Wenn IPv6
        /// gar nicht verfuegbar ist, ist eine leere Spalte nur Rauschen.
        /// </summary>
        public bool ShouldHideIpv6Ui =>
            Availability is Ipv6Availability.NotSupportedByOperatingSystem
                         or Ipv6Availability.DisabledOnAdapter
                         or Ipv6Availability.NoAddress;

        public override string ToString() => $"{Availability}: {Reason}";

        // ------------------------------------------------------------ Pruefung

        /// <summary>Kann das Betriebssystem ueberhaupt IPv6?</summary>
        public static bool OperatingSystemSupportsIpv6 => Socket.OSSupportsIPv6;

        /// <summary>
        /// Prueft einen einzelnen Adapter. Wirft nicht - ein Adapter, der
        /// waehrend der Pruefung verschwindet, ergibt
        /// <see cref="Ipv6Availability.Unknown"/>.
        /// </summary>
        public static Ipv6Readiness ForInterface(NetworkInterface? nic)
        {
            if (!Socket.OSSupportsIPv6)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.NotSupportedByOperatingSystem,
                    Reason = "Das Betriebssystem unterstuetzt kein IPv6."
                };
            }

            if (nic is null)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = "Kein Netzwerkadapter ausgewaehlt."
                };
            }

            try
            {
                if (!nic.Supports(NetworkInterfaceComponent.IPv6))
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.DisabledOnAdapter,
                        Reason = $"IPv6 ist am Adapter \"{nic.Name}\" nicht gebunden - im Adapter abgeschaltet."
                    };
                }

                bool hasLinkLocal = false;
                bool hasUniqueLocal = false;
                bool hasGlobal = false;

                foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;

                    IpAddressInfo info = IpAddressAnalyzer.Analyze(unicast.Address);
                    switch (info.Scope)
                    {
                        case IpAddressScope.LinkLocal: hasLinkLocal = true; break;
                        case IpAddressScope.UniqueLocal: hasUniqueLocal = true; break;
                        case IpAddressScope.Global: hasGlobal = true; break;
                    }
                }

                if (hasGlobal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.Global,
                        Reason = "IPv6 vollstaendig nutzbar - globale Adresse vorhanden."
                    };
                }

                if (hasUniqueLocal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.UniqueLocalOnly,
                        Reason = "Nur lokal eindeutige Adresse (ULA) - kein Zugang zum globalen IPv6-Netz."
                    };
                }

                if (hasLinkLocal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.LinkLocalOnly,
                        Reason = "Nur Link-Local - im Netz kuendigt kein Router ein Praefix an. " +
                                 "Das eigene Segment laesst sich trotzdem vollstaendig untersuchen."
                    };
                }

                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.NoAddress,
                    Reason = $"Der Adapter \"{nic.Name}\" hat keine einzige IPv6-Adresse."
                };
            }
            catch (NetworkInformationException ex)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = $"IPv6-Status nicht ermittelbar: {ex.Message}"
                };
            }
            catch (PlatformNotSupportedException ex)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = $"IPv6-Status nicht ermittelbar: {ex.Message}"
                };
            }
        }
    }
}
