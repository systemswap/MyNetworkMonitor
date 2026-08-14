using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Eine Rubrik in der Auswahl. Die Namen kommen aus den
    /// Dienstdefinitionen des Nutzers - dieselbe Gliederung, die die bisherige
    /// Anwendung schon benutzt hat.
    /// </summary>
    public sealed class GroupableServiceGroup
    {
        public required string Name { get; init; }

        public ObservableCollection<GroupableService> Services { get; } = [];
    }

    /// <summary>
    /// Ein Dienst in der Auswahl "welche Dienste werden zusammengefasst".
    /// Angehakt heisst: zaehlt in der Tabelle zum "+n", statt einzeln zu
    /// erscheinen.
    /// </summary>
    public partial class GroupableService : ObservableObject
    {
        /// <summary>
        /// Der Schluessel des Dienstes - so, wie er in den Definitionen und in
        /// <see cref="ServiceDisplay.Grouped"/> steht. Nicht fuer die Anzeige;
        /// dafuer ist <see cref="DisplayName"/> da.
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// Was in der Oberflaeche steht. Standardmaessig der Name, aber ein
        /// Dienst kann einen sprechenderen tragen - "S7 PLC (SPS)" statt "S7".
        /// Der Schluessel <see cref="Name"/> bleibt davon unberuehrt, damit die
        /// Gruppierungslogik weiter greift.
        /// </summary>
        public string? DisplayNameOverride { get; init; }

        public string DisplayName => DisplayNameOverride ?? Name;

        [ObservableProperty] private bool _isGrouped;

        /// <summary>
        /// Wohin eine Aenderung geschrieben wird, wenn es nicht der
        /// Normalfall ist - der Name in <see cref="ServiceDisplay.Grouped"/>.
        /// Die Rubrik "offene Ports" trifft keinen einzelnen Dienstnamen,
        /// sondern eigene Schalter; ohne diesen Umweg muesste die Auswertung
        /// den Namen kennen und danach unterscheiden, statt dass jeder
        /// Eintrag selbst mitbringt, was ein Haken an ihm bedeutet.
        /// </summary>
        public Action<bool>? OnChanged { get; init; }

        public override string ToString() => $"{Name}{(IsGrouped ? " (grouped)" : string.Empty)}";
    }
}
