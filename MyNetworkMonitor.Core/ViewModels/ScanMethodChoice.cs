using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Ein Verfahren in der Schublade: angehakt oder nicht, und ob es unter den
    /// aktuellen Bedingungen ueberhaupt laufen kann.
    /// <para>
    /// <see cref="Availability"/> wird bei jeder Aenderung der Bereichsauswahl
    /// neu bestimmt. Ein Verfahren, das nicht laufen kann, wird ausgegraut und
    /// traegt <see cref="BlockReason"/> als Erklaerung - statt still zu
    /// scheitern, wenn man auf Start drueckt.
    /// </para>
    /// </summary>
    public partial class ScanMethodChoice : ObservableObject
    {
        public required IScanMethod Method { get; init; }

        public string Id => Method.Id;
        public string DisplayName => Method.DisplayName;
        public ScanPhase Phase => Method.Phase;
        public FamilySupport Families => Method.Families;
        public bool IsPassive => Method.IsPassive;

        [ObservableProperty] private bool _isSelected;

        /// <summary>
        /// Dieses Verfahren soll nur die Geraete abfragen, die schon in der
        /// Tabelle stehen.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Das Verfahren geht eine Zielliste durch und laesst sich darum
        /// ueberhaupt beschraenken. Fuer SSDP, mDNS und die ARP-Tabelle gibt es
        /// nichts zu kuerzen - sie bekommen kein Kaestchen.
        /// </summary>
        public bool CanRestrictToKnown => Method.EnumeratesTargets;

        [ObservableProperty] private ScanMethodAvailability _availability = ScanMethodAvailability.Available;

        /// <summary>Kann angehakt werden.</summary>
        public bool IsEnabled => Availability.CanRun;

        /// <summary>Erklaerung fuer den Tooltip. Leer, wenn das Verfahren laeuft.</summary>
        public string BlockReason => Availability.CanRun ? string.Empty : Availability.Reason;

        /// <summary>Nur IPv6 - traegt in der Oberflaeche die Indigo-Kennzeichnung.</summary>
        public bool IsIpv6Only => Families == FamilySupport.IPv6;

        /// <summary>Kann beide Familien - selten, aber sichtbar zu machen.</summary>
        public bool IsDualStack => Families == FamilySupport.Both;

        partial void OnAvailabilityChanged(ScanMethodAvailability value)
        {
            OnPropertyChanged(nameof(IsEnabled));
            OnPropertyChanged(nameof(BlockReason));

            // Ein Verfahren, das nicht laufen kann, bleibt nicht angehakt -
            // sonst suggeriert die Auswahl etwas, das nicht passiert.
            if (!value.CanRun) IsSelected = false;
        }
    }
}
