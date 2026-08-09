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
        public required string Name { get; init; }

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
