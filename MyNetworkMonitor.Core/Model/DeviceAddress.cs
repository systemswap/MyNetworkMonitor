using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Eine Adresse an einem Geraet, samt allem, was nicht aus der Adresse
    /// selbst folgt: Zustand, Lebensdauern und wann sie zuletzt gesehen wurde.
    /// <para>
    /// Der Zeitbezug ist unter IPv6 keine Zugabe, sondern Pflicht. Adressen mit
    /// Privacy Extensions wechseln taeglich - ohne <see cref="FirstSeen"/> und
    /// <see cref="LastSeen"/> zaehlt ein Mobiltelefon ueber eine Woche als
    /// sieben Geraete.
    /// </para>
    /// </summary>
    public partial class DeviceAddress : ObservableObject
    {
        public required IpAddressInfo Info { get; init; }

        /// <summary>Wie die Adresse an das Interface kam - laut Betriebssystem, nicht geraten.</summary>
        [ObservableProperty] private AddressOrigin _origin = AddressOrigin.Unknown;

        [ObservableProperty] private AddressState _state = AddressState.Unknown;

        /// <summary>
        /// Ab wann die Adresse nicht mehr gueltig ist. Aus der Valid Lifetime
        /// des Router Advertisements bzw. der DHCP-Zuteilung. <c>null</c>, wenn
        /// unbegrenzt oder unbekannt.
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _validUntil;

        /// <summary>
        /// Ab wann die Adresse nur noch fuer bestehende Verbindungen taugt
        /// (Preferred Lifetime). Liegt vor <see cref="ValidUntil"/>.
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _preferredUntil;

        [ObservableProperty] private DateTimeOffset _firstSeen;
        [ObservableProperty] private DateTimeOffset _lastSeen;

        /// <summary>Welches Verfahren die Adresse geliefert hat.</summary>
        [ObservableProperty] private string _discoveredBy = string.Empty;

        /// <summary>
        /// Die Adresse hat geantwortet, seit sie zuletzt geprueft wurde.
        /// Getrennt von <see cref="LastSeen"/>, weil eine Adresse auch passiv
        /// beobachtet werden kann, ohne dass jemand sie angesprochen hat.
        /// </summary>
        [ObservableProperty] private bool _isResponding;

        /// <summary>Abgelaufen laut Lebensdauer - unabhaengig davon, ob sie noch benutzt wird.</summary>
        public bool IsExpired => ValidUntil is { } until && until <= DateTimeOffset.Now;

        /// <summary>
        /// Verbleibende Gueltigkeit als Anteil zwischen 0 und 1, fuer den
        /// Balken in der Oberflaeche. <c>null</c> bei unbegrenzter Lebensdauer.
        /// </summary>
        public double? RemainingLifetimeFraction
        {
            get
            {
                if (ValidUntil is not { } until) return null;

                double total = (until - FirstSeen).TotalSeconds;
                if (total <= 0) return 0;

                double left = (until - DateTimeOffset.Now).TotalSeconds;
                return Math.Clamp(left / total, 0, 1);
            }
        }

        public override string ToString() => Info.Canonical;
    }
}
