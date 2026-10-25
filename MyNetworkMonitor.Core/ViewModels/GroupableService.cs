// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// A category in the grouping selection. The names come from the
    /// configured service definitions and follow their structure.
    /// </summary>
    public sealed class GroupableServiceGroup
    {
        /// <summary>The category name.</summary>
        public required string Name { get; init; }

        /// <summary>The services in this category.</summary>
        public ObservableCollection<GroupableService> Services { get; } = [];
    }

    /// <summary>
    /// A service in the "which services are grouped" selection. When checked,
    /// the service counts towards the "+n" in the table instead of appearing
    /// on its own.
    /// </summary>
    public partial class GroupableService : ObservableObject
    {
        /// <summary>
        /// The service key as it appears in the definitions and in
        /// <see cref="ServiceDisplay.Grouped"/>. Not meant for display;
        /// use <see cref="DisplayName"/> for that.
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// Optional label shown in the UI instead of the key, e.g. "S7 PLC (SPS)"
        /// instead of "S7". The key <see cref="Name"/> is unaffected, so the
        /// grouping logic keeps matching.
        /// </summary>
        public string? DisplayNameOverride { get; init; }

        /// <summary>The label shown in the UI: <see cref="DisplayNameOverride"/> if set, otherwise <see cref="Name"/>.</summary>
        public string DisplayName => DisplayNameOverride ?? Name;

        [ObservableProperty] private bool _isGrouped;

        /// <summary>
        /// Where a change is written when it does not go to the usual target,
        /// the name in <see cref="ServiceDisplay.Grouped"/>.
        /// The "open ports" category does not map to a single service name but
        /// to separate switches; with this callback each entry carries what a
        /// check mark on it means, so the evaluation does not have to know and
        /// distinguish the names.
        /// </summary>
        public Action<bool>? OnChanged { get; init; }

        public override string ToString() => $"{Name}{(IsGrouped ? " (grouped)" : string.Empty)}";
    }
}
