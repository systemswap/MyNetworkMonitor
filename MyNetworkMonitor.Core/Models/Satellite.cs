// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// A satellite: an instance of this application that runs as a service in
    /// another network segment and scans from there.
    /// <para>
    /// The design is described in SATELLIT.md. Key to understanding this
    /// class: <b>the satellite connects to this installation</b>, not the other
    /// way round. Address and port are therefore not settings here but
    /// observations. Its identity is the fingerprint of its key, which
    /// survives every address change.
    /// </para>
    /// <para>
    /// An entry is created when a satellite with an unknown fingerprint
    /// connects for the first time; it then waits for approval.
    /// </para>
    /// </summary>
    public partial class Satellite : ObservableObject
    {
        /// <summary>
        /// The immutable identifier that <c>ScanScope.ScannedBy</c> refers to.
        /// Assigned on creation and never displayed.
        /// <para>
        /// A range must not refer to the <em>name</em>: the satellite can change
        /// its name itself, and a rename would silently break every range
        /// assignment - the range would simply no longer be scanned. The
        /// fingerprint is not suitable either, because it changes when the
        /// satellite issues itself a new key.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _id = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Display name. Freely changeable - assignments depend on
        /// <see cref="Id"/>, not on the name.
        /// </summary>
        [ObservableProperty] private string _name = string.Empty;

        /// <summary>
        /// What this satellite is for - a note only, for example
        /// "Cabinet IDF2, behind the plant firewall".
        /// </summary>
        [ObservableProperty] private string _note = string.Empty;

        /// <summary>
        /// Fingerprint of its key - its actual identity. Empty as long as it
        /// has never connected.
        /// </summary>
        [ObservableProperty] private string _fingerprint = string.Empty;

        /// <summary>
        /// Approved on this installation. Without approval it receives no jobs,
        /// even when connected - see SATELLIT.md, section 4.
        /// </summary>
        [ObservableProperty] private bool _approved;

        /// <summary>When it last reported. Display only.</summary>
        [ObservableProperty] private DateTimeOffset? _lastSeen;

        /// <summary>Its application version, from the greeting. Display only.</summary>
        [ObservableProperty] private string _version = string.Empty;

        /// <summary>Its operating system, from the greeting. Display only.</summary>
        [ObservableProperty] private string _os = string.Empty;

        /// <summary>The address it last connected from. Display only.</summary>
        [ObservableProperty] private string _remoteAddress = string.Empty;

        // --- Its location, from its greeting -----------------------------------
        //
        // Overwritten on every login, not only the first one: after a restart
        // or a new DHCP lease it would otherwise be outdated. It is persisted
        // anyway so that the selection shows something while the satellite is
        // offline.

        /// <summary>Its computer name, as reported by itself.</summary>
        [ObservableProperty] private string _siteHostName = string.Empty;

        /// <summary>Its domain. Empty if it belongs to none.</summary>
        [ObservableProperty] private string _siteDomain = string.Empty;

        /// <summary>Its IPv4 addresses, comma-separated.</summary>
        [ObservableProperty] private string _siteIpv4 = string.Empty;

        /// <summary>Its IPv6 addresses, comma-separated.</summary>
        [ObservableProperty] private string _siteIpv6 = string.Empty;

        /// <summary>
        /// The network that best describes its location, for example
        /// <c>192.0.2.0/24</c>. Shown after the name in the selection.
        /// </summary>
        [ObservableProperty] private string _siteNetwork = string.Empty;

        /// <summary>All of its networks, comma-separated - for the tooltip.</summary>
        [ObservableProperty] private string _siteNetworks = string.Empty;

        /// <summary>
        /// How it appears in the "Scanned by satellite" selection: name and
        /// network.
        /// <para>
        /// Without the network, assigning a range shows only a name, leaving it
        /// to guesswork whether this satellite sits in the right segment.
        /// </para>
        /// </summary>
        public string PickerText =>
            string.IsNullOrWhiteSpace(SiteNetwork) ? Name : $"{Name}  ·  {SiteNetwork}";

        partial void OnNameChanged(string value) => OnPropertyChanged(nameof(PickerText));
        partial void OnSiteNetworkChanged(string value) => OnPropertyChanged(nameof(PickerText));

        // --- What it should scan ---------------------------------------------

        /// <summary>
        /// "Only devices from the table" for all scan methods of this satellite.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// The scan methods that, on this satellite, query only what has
        /// already been found - set per method.
        /// <para>
        /// Copied once from the main settings when the entry is created and
        /// independent afterwards: what a satellite should scan depends on its
        /// segment, not on what was last configured here. A later change to the
        /// main settings therefore deliberately does <em>not</em> affect
        /// existing satellites.
        /// </para>
        /// </summary>
        public HashSet<string> OnlyKnownTargetsFor { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Whether the DNS cross-check on this satellite checks only the
        /// devices that responded during the run.
        /// <para>
        /// Not a scan method but part of the name scan - shown in the same box
        /// because it answers the same question and saves the same time. When
        /// off, every old row of the table is checked as well, which is how
        /// names are found that still resolve although the device is long gone.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckOnlyKnownTargets = true;

        /// <summary>
        /// The scan methods this satellite should restrict, ready for the job
        /// text.
        /// </summary>
        /// <param name="restrictable">All scan methods that can be restricted.</param>
        /// <returns>All of <paramref name="restrictable"/> if <see cref="OnlyKnownTargets"/> is set; otherwise <see cref="OnlyKnownTargetsFor"/>.</returns>
        public IEnumerable<string> EffectiveOnlyKnownFor(IEnumerable<string> restrictable) =>
            OnlyKnownTargets ? restrictable : OnlyKnownTargetsFor;

        /// <summary>
        /// Whether a connection currently exists. Not persisted: after a
        /// restart no satellite is connected until it reports again.
        /// </summary>
        [ObservableProperty] private bool _isConnected;

        // --- Running job, none of it is persisted ----------------------------

        /// <summary>Identifier of the running job, or empty.</summary>
        [ObservableProperty] private string _jobId = string.Empty;

        /// <summary>0 to 100 - shows that the satellite is working.</summary>
        [ObservableProperty] private int _progressPercent;

        /// <summary>The scan method currently running.</summary>
        [ObservableProperty] private string _progressCurrent = string.Empty;

        /// <summary>The steps already completed.</summary>
        [ObservableProperty] private string _progressDone = string.Empty;

        /// <summary>The steps still pending.</summary>
        [ObservableProperty] private string _progressPending = string.Empty;

        /// <summary>The position of the running scan method within the job.</summary>
        [ObservableProperty] private int _progressStep;

        /// <summary>The number of scan methods in the job.</summary>
        [ObservableProperty] private int _progressSteps;

        // --- The three counters of the running scan method -------------------

        /// <summary>Requests sent by the running scan method.</summary>
        [ObservableProperty] private int _progressSent;

        /// <summary>Targets that have responded.</summary>
        [ObservableProperty] private int _progressAnswered;

        /// <summary>Total targets of the running scan method.</summary>
        [ObservableProperty] private int _progressTotal;

        /// <summary>
        /// When the last progress report arrived. The satellite reports even
        /// when nothing has changed - if this time stops advancing, the
        /// connection is stuck, not the scan.
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _progressAt;

        /// <summary>The three counters are available only after the first report.</summary>
        public bool HasCounts => ProgressTotal > 0;

        /// <summary>"3 / 12" - the running scan method out of how many.</summary>
        public string StepText =>
            ProgressSteps <= 0 ? string.Empty : $"{Math.Max(ProgressStep, 1)} / {ProgressSteps}";

        /// <summary>
        /// Recomputes the age text. It depends on the clock, not on a property -
        /// without this trigger it would stay at the value of the last report,
        /// precisely when no more reports arrive.
        /// </summary>
        public void RefreshProgressAge() => OnPropertyChanged(nameof(ProgressAgeText));

        /// <summary>How long ago the last report arrived, in words.</summary>
        public string ProgressAgeText
        {
            get
            {
                if (ProgressAt is null) return string.Empty;

                TimeSpan age = DateTimeOffset.UtcNow - ProgressAt.Value;

                if (age < TimeSpan.FromSeconds(15)) return "just now";
                if (age < TimeSpan.FromMinutes(1)) return $"{(int)age.TotalSeconds}s ago";
                if (age < TimeSpan.FromHours(1)) return $"{(int)age.TotalMinutes} min ago";

                return ProgressAt.Value.LocalDateTime.ToString("g");
            }
        }

        /// <summary>A job is currently running.</summary>
        public bool IsBusy => !string.IsNullOrEmpty(JobId);

        partial void OnJobIdChanged(string value)
        {
            OnPropertyChanged(nameof(IsBusy));
            RaiseStatus();
        }

        partial void OnProgressPercentChanged(int value) => OnPropertyChanged(nameof(StatusText));
        partial void OnProgressCurrentChanged(string value) => OnPropertyChanged(nameof(StatusText));

        partial void OnProgressStepChanged(int value) => OnPropertyChanged(nameof(StepText));
        partial void OnProgressStepsChanged(int value) => OnPropertyChanged(nameof(StepText));

        partial void OnProgressTotalChanged(int value)
        {
            OnPropertyChanged(nameof(HasCounts));
            OnPropertyChanged(nameof(StatusText));
        }

        partial void OnProgressSentChanged(int value) => OnPropertyChanged(nameof(StatusText));
        partial void OnProgressAnsweredChanged(int value) => OnPropertyChanged(nameof(StatusText));
        partial void OnProgressAtChanged(DateTimeOffset? value) => OnPropertyChanged(nameof(ProgressAgeText));

        /// <summary>
        /// The current state of this entry - one sentence for the list, so the
        /// state need not be pieced together from four fields.
        /// </summary>
        public string StatusText
        {
            get
            {
                // During a job the same information as the local command bar:
                // which scan method, how far, and the three counters -
                // "Ping 40 %  ·  102 / 17 / 254". The percentage belongs to the
                // running scan method, not to the whole job.
                if (IsBusy)
                {
                    List<string> parts = [];

                    string head = $"{ProgressCurrent} {ProgressPercent} %".TrimStart();
                    parts.Add(head);

                    if (HasCounts) parts.Add($"{ProgressSent} / {ProgressAnswered} / {ProgressTotal}");

                    string step = StepText;
                    if (step.Length > 0) parts.Add($"step {step}");

                    return string.Join("  ·  ", parts);
                }

                if (IsConnected && Approved) return "Connected";
                if (IsConnected) return "Waiting for approval";
                if (string.IsNullOrWhiteSpace(Fingerprint)) return "Never connected";
                if (!Approved) return "Not approved";

                return LastSeen is null
                    ? "Offline"
                    : $"Offline since {LastSeen.Value.LocalDateTime:g}";
            }
        }

        /// <summary>It has connected at least once and has an identity.</summary>
        public bool IsKnown => !string.IsNullOrWhiteSpace(Fingerprint);

        /// <summary>It is waiting for approval.</summary>
        public bool NeedsApproval => IsKnown && !Approved;

        partial void OnIsConnectedChanged(bool value) => RaiseStatus();
        partial void OnApprovedChanged(bool value) => RaiseStatus();
        partial void OnFingerprintChanged(string value) => RaiseStatus();
        partial void OnLastSeenChanged(DateTimeOffset? value) => RaiseStatus();

        private void RaiseStatus()
        {
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(IsKnown));
            OnPropertyChanged(nameof(NeedsApproval));
        }
    }
}
