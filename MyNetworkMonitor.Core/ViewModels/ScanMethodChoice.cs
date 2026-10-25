using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// A scan method in the method drawer: whether it is checked and whether it
    /// can run under the current conditions.
    /// <para>
    /// <see cref="Availability"/> is re-evaluated whenever the scope selection
    /// changes. A method that cannot run is greyed out and carries
    /// <see cref="BlockReason"/> as an explanation instead of failing silently
    /// when the scan is started.
    /// </para>
    /// </summary>
    public partial class ScanMethodChoice : ObservableObject
    {
        /// <summary>The scan method this choice represents.</summary>
        public required IScanMethod Method { get; init; }

        /// <summary>The method's identifier.</summary>
        public string Id => Method.Id;
        /// <summary>The method's display name.</summary>
        public string DisplayName => Method.DisplayName;
        /// <summary>The phase in which the method runs.</summary>
        public ScanPhase Phase => Method.Phase;
        /// <summary>The address families the method supports.</summary>
        public FamilySupport Families => Method.Families;
        /// <summary>The method only listens and sends nothing.</summary>
        public bool IsPassive => Method.IsPassive;

        /// <summary>The method is checked.</summary>
        [ObservableProperty] private bool _isSelected;

        /// <summary>
        /// The method queries only the devices that are already in the table.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// The method walks a target list and can therefore be restricted at
        /// all. SSDP, mDNS and the ARP table have nothing to restrict and get
        /// no check box.
        /// </summary>
        public bool CanRestrictToKnown => Method.EnumeratesTargets;

        /// <summary>Whether the method can run under the current conditions, and why not.</summary>
        [ObservableProperty] private ScanMethodAvailability _availability = ScanMethodAvailability.Available;

        /// <summary>
        /// The method can be checked. Only a hard block disables the check box:
        /// missing administrator rights, no adapter, no raw socket. "No matching
        /// target" (<see cref="ScanMethodState.NotApplicable"/>) does not disable
        /// it: that depends on the selected scope, and the methods must remain
        /// configurable without a scope, e.g. to rescan a single device from the
        /// table. Whether a method actually runs is decided by the run against
        /// its own targets, not by this check box.
        /// </summary>
        public bool IsEnabled => Availability.State != ScanMethodState.Blocked;

        /// <summary>Empty when the method can run.</summary>
        public string BlockReason => Availability.CanRun ? string.Empty : Availability.Reason;

        /// <summary>What the method finds and what it is used for.</summary>
        public string Explanation => Method.Explanation;

        /// <summary>
        /// The tooltip text: always the explanation, followed by the reason if
        /// the method cannot run right now.
        /// <para>
        /// Both belong together. The block reason alone would leave runnable
        /// methods without a tooltip, although those are the ones where the
        /// question "should this be checked?" arises. Conversely, the
        /// explanation alone does not tell why a blocked method is greyed out.
        /// </para>
        /// </summary>
        public string Hint
        {
            get
            {
                if (BlockReason.Length == 0) return Explanation;

                // Two different situations: hard block (check box disabled) or
                // merely "does not fit right now" (check box stays, but the
                // method does not run with the current settings).
                string lead = Availability.State == ScanMethodState.Blocked
                    ? "Not available right now:"
                    : "Won't run as things are set:";

                return $"{Explanation}\n\n{lead} {BlockReason}";
            }
        }

        /// <summary>IPv6 only; marked in indigo in the UI.</summary>
        public bool IsIpv6Only => Families == FamilySupport.IPv6;

        /// <summary>Shown indented below the preceding method; see <see cref="IScanMethod.Indented"/>.</summary>
        public bool Indented => Method.Indented;

        /// <summary>Supports both address families; rare, but marked in the UI.</summary>
        public bool IsDualStack => Families == FamilySupport.Both;

        // ---------------------------------------------------------- Progress

        /// <summary>Number of requests this method has sent.</summary>
        [ObservableProperty] private int _sent;

        /// <summary>Number of targets that have answered.</summary>
        [ObservableProperty] private int _responded;

        /// <summary>Total number of targets.</summary>
        [ObservableProperty] private int _total;

        /// <summary>The method has reported progress in this run.</summary>
        [ObservableProperty] private bool _hasProgress;

        /// <summary>
        /// The three numbers side by side: sent, answered, total.
        /// <para>
        /// Two numbers are not enough. "254 / 254" reads as "finished" while
        /// everything has merely been sent and answers are still awaited; only
        /// the middle number shows the result.
        /// </para>
        /// </summary>
        public string ProgressText => HasProgress ? $"{Sent} / {Responded} / {Total}" : string.Empty;

        partial void OnSentChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnRespondedChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnTotalChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnHasProgressChanged(bool value) => OnPropertyChanged(nameof(ProgressText));

        /// <summary>Resets the counters before a new run.</summary>
        public void ResetProgress()
        {
            Sent = Responded = Total = 0;
            HasProgress = false;
        }

        /// <summary>
        /// The method is checked <em>and</em> can run right now. This is what a
        /// run actually executes.
        /// <para>
        /// Kept separate from the check mark because the two mean different
        /// things: <see cref="IsSelected"/> is the chosen setting,
        /// <see cref="IsEnabled"/> the current situation. A block therefore
        /// never clears the check mark; clearing it would lose the choice
        /// permanently, even when the method becomes runnable again moments
        /// later. Selecting a different scope is enough to trigger this: the
        /// availability check runs, a method is briefly blocked, and the
        /// selection would silently end up empty.
        /// </para>
        /// </summary>
        public bool IsEffective => IsSelected && IsEnabled;

        partial void OnAvailabilityChanged(ScanMethodAvailability value)
        {
            OnPropertyChanged(nameof(IsEnabled));
            OnPropertyChanged(nameof(BlockReason));
            OnPropertyChanged(nameof(Hint));
            OnPropertyChanged(nameof(IsEffective));
        }

        partial void OnIsSelectedChanged(bool value) => OnPropertyChanged(nameof(IsEffective));
    }
}
