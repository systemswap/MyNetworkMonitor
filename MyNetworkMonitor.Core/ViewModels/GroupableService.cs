using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Ein Dienst in der Auswahl "welche Dienste werden zusammengefasst".
    /// Angehakt heisst: zaehlt in der Tabelle zum "+n", statt einzeln zu
    /// erscheinen.
    /// </summary>
    public partial class GroupableService : ObservableObject
    {
        public required string Name { get; init; }

        [ObservableProperty] private bool _isGrouped;

        public override string ToString() => $"{Name}{(IsGrouped ? " (grouped)" : string.Empty)}";
    }
}
