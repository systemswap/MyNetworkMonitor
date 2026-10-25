// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Persistence;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Management of the scan scopes: list on the left, form on the right.
    /// <para>
    /// Works on <em>the same</em> collection as the scope selection in the
    /// command bar. A scope created or renamed here appears in the drop-down
    /// immediately; a second list that has to be kept in sync manually would
    /// be another source of errors.
    /// </para>
    /// <para>
    /// Saved to <c>ipGroups.xml</c>. Scopes that this format cannot represent
    /// (the adapter scope, an IPv6 prefix) are skipped instead of being saved
    /// incompletely.
    /// </para>
    /// </summary>
    public partial class ScopeEditorViewModel : ObservableObject
    {
        private readonly ObservableCollection<ScanScope> _scopes;
        private string _xmlPath = string.Empty;

        /// <summary>
        /// Blocks saving while loading. Without it every added scope would
        /// rewrite the file, the first write coming from a half-filled list.
        /// </summary>
        private bool _loading;

        /// <summary>Creates the editor on the shared scope collection.</summary>
        /// <param name="scopes">The scope collection shared with the command bar.</param>
        /// <exception cref="ArgumentNullException"><paramref name="scopes"/> is <see langword="null"/>.</exception>
        public ScopeEditorViewModel(ObservableCollection<ScanScope> scopes)
        {
            _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));

            // Listen to every scope, not only the one in the form: the Active
            // check mark is set in the command bar, and without this it would
            // be lost on every restart.
            _scopes.CollectionChanged += (_, e) =>
            {
                foreach (ScanScope scope in e.OldItems?.OfType<ScanScope>() ?? [])
                {
                    scope.PropertyChanged -= OnScopeEdited;
                }
                foreach (ScanScope scope in e.NewItems?.OfType<ScanScope>() ?? [])
                {
                    scope.PropertyChanged += OnScopeEdited;
                }
            };
        }

        /// <summary>
        /// Raised when a scope was checked or unchecked. The command bar then
        /// recalculates target count, duration and method availability.
        /// </summary>
        public event Action? SelectionChanged;

        /// <summary>The scan scopes, including the adapter scope at the top.</summary>
        public ObservableCollection<ScanScope> Scopes => _scopes;

        /// <summary>The scope shown in the form.</summary>
        [ObservableProperty] private ScanScope? _selected;

        /// <summary>Without a selection the form stays empty instead of half usable.</summary>
        public bool HasSelection => Selected is not null;

        /// <summary>
        /// The adapter scope is created at startup, not saved, so it can be
        /// neither deleted nor meaningfully edited.
        /// </summary>
        public bool IsEditable => Selected is not null && Selected.Kind == ScanScopeKind.IPv4Range;

        /// <summary>What is wrong with the form. Empty when everything is valid.</summary>
        [ObservableProperty] private string _problem = string.Empty;

        /// <summary>The status line text.</summary>
        [ObservableProperty] private string _status = string.Empty;

        partial void OnSelectedChanged(ScanScope? value)
        {
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(IsEditable));
            Validate();
        }

        /// <summary>
        /// Every change in the form is validated and saved immediately.
        /// <para>
        /// No save button: the list on the left already shows what applies, and
        /// a forgotten button would lose a whole form's work. Invalid
        /// intermediate states, such as a half-typed address, are saved but
        /// flagged and skipped when scanning.
        /// </para>
        /// </summary>
        private void OnScopeEdited(object? sender, PropertyChangedEventArgs e)
        {
            // RangeText is derived and raised along with FirstIP/LastIP; saving
            // on it would write every change twice.
            if (e.PropertyName == nameof(ScanScope.RangeText)) return;

            if (e.PropertyName == nameof(ScanScope.IsSelected)) SelectionChanged?.Invoke();

            if (ReferenceEquals(sender, Selected)) Validate();

            Save();
        }

        // ------------------------------------------------------------ Loading

        /// <summary>
        /// Reads the saved scopes and puts the adapter scope first, so there is
        /// something to scan without any setup.
        /// </summary>
        /// <param name="xmlPath">The <c>ipGroups.xml</c> file; also the target for later saves.</param>
        public void Load(string xmlPath)
        {
            _xmlPath = xmlPath;
            _loading = true;

            try
            {
                _scopes.Clear();

                _scopes.Add(new ScanScope
                {
                    Index = 0,
                    Kind = ScanScopeKind.NetworkInterface,
                    GroupDescription = "Local network",
                    DeviceDescription = "from the active adapter",
                    IsSelected = true
                });

                if (!File.Exists(xmlPath)) return;

                // Build the table with *the* schema that is also used for
                // saving, not with IPGroupData.
                //
                // ReadXml does not add unknown columns to a table that already
                // has columns: whatever the table does not know is dropped on
                // reading. IPGroupData knows neither ScannedBy nor LastScanned.
                // With it, both are in the file but never come back: the
                // assignment of a scope to a satellite does not survive a
                // restart, and the scope is silently scanned from here again.
                System.Data.DataTable data = IpGroupTable.CreateTable();
                data.ReadXml(xmlPath);

                int index = 1;

                foreach (IpGroup group in IpGroupTable.ReadRows(data))
                {
                    ScanScope scope = ScanScope.FromIpGroup(group);
                    scope.Index = index++;
                    _scopes.Add(scope);
                }

                Status = $"{_scopes.Count - 1} ranges loaded.";
            }
            catch (Exception ex)
            {
                // A missing or damaged file must not prevent startup; the
                // adapter scope is enough to work with.
                Status = $"Ranges could not be loaded: {ex.Message}";
            }
            finally
            {
                _loading = false;
            }
        }

        // ------------------------------------------------------------- Saving

        /// <summary>
        /// How long to wait after the last change before writing. The text
        /// fields report every keystroke; without this delay every character
        /// would cause a file access.
        /// </summary>
        private static readonly TimeSpan SaveDelay = TimeSpan.FromMilliseconds(600);

        private Timer? _saveTimer;

        /// <summary>
        /// The state to be written. Captured when the save is requested, not
        /// when writing: the timer runs on its own thread, and the scope list
        /// belongs to the UI.
        /// </summary>
        private List<IpGroup> _pending = [];

        /// <summary>
        /// Whether anything has changed since loading. Without this guard,
        /// merely opening and closing the application would rewrite the file,
        /// an unnecessary risk for the saved scopes.
        /// </summary>
        private bool _dirty;

        /// <summary>
        /// Captures the current state for saving and writes it after
        /// <see cref="SaveDelay"/>. Called after every change, including a
        /// check mark in the command bar, which would otherwise be lost on
        /// restart.
        /// </summary>
        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath)) return;

            _dirty = true;

            // Capture while still on the UI thread.
            _pending =
            [
                .. _scopes.OrderBy(s => s.Index)
                          .Select(s => s.ToIpGroup())
                          .Where(g => g is not null)
                          .Select(g => g!)
            ];

            _saveTimer ??= new Timer(_ => Flush(), null, Timeout.Infinite, Timeout.Infinite);
            _saveTimer.Change(SaveDelay, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Writes the captured state. Runs on the timer thread.</summary>
        private void Flush()
        {
            try
            {
                IpGroupTable.SaveXml(_pending, _xmlPath);
            }
            catch (Exception ex)
            {
                Status = $"Ranges could not be saved: {ex.Message}";
            }
        }

        /// <summary>
        /// Writes immediately without waiting for the delay; used when the
        /// window closes, where the timer would never fire again.
        /// </summary>
        public void SaveNow()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath) || !_dirty) return;

            Save();
            _saveTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            Flush();
        }

        // ----------------------------------------------------------- Commands

        /// <summary>
        /// Adds a range for the network this machine is in (the first IPv4
        /// network with a gateway, narrowed to a /24, see
        /// <see cref="SiteInfo.SuggestedRange"/>). Without such a network it
        /// falls back to the most common home network.
        /// </summary>
        [RelayCommand]
        private void Add()
        {
            SiteAddress? own = SiteInfo.Read().Ipv4.FirstOrDefault(a => a.HasGateway);
            (string First, string Last) range =
                (own is null ? null : SiteInfo.SuggestedRange(own.Address, own.PrefixLength))
                ?? ("192.168.1.1", "192.168.1.254");

            ScanScope scope = new()
            {
                Index = NextIndex(),
                Kind = ScanScopeKind.IPv4Range,
                GroupDescription = "New range",
                FirstIP = range.First,
                LastIP = range.Last,
                IsSelected = false
            };

            _scopes.Add(scope);
            Selected = scope;
            Save();

            Status = "Range added.";
        }

        /// <summary>
        /// A new scope usually differs from the previous one only in the third
        /// octet, so copying is quicker than filling in the form again.
        /// </summary>
        [RelayCommand]
        private void Duplicate()
        {
            if (Selected is null) return;

            ScanScope copy = new()
            {
                Index = NextIndex(),
                Kind = ScanScopeKind.IPv4Range,
                GroupDescription = $"{Selected.GroupDescription} (copy)",
                DeviceDescription = Selected.DeviceDescription,
                FirstIP = Selected.FirstIP,
                LastIP = Selected.LastIP,
                Domain = Selected.Domain,
                DnsServers = Selected.DnsServers,
                GatewayIP = Selected.GatewayIP,
                ScannedBy = Selected.ScannedBy,
                AutomaticScan = Selected.AutomaticScan,
                ScanIntervalMinutes = Selected.ScanIntervalMinutes,
                // LastScanned is deliberately not copied: the copy has never
                // run and would otherwise count as freshly scanned.
                IsSelected = false
            };

            _scopes.Add(copy);
            Selected = copy;
            Save();

            Status = "Range duplicated.";
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null || !IsEditable) return;

            string name = Selected.GroupDescription;
            int position = _scopes.IndexOf(Selected);

            _scopes.Remove(Selected);

            // Select the nearest row instead of falling back to an empty form;
            // work usually continues right away.
            Selected = _scopes.Count == 0
                ? null
                : _scopes[Math.Min(position, _scopes.Count - 1)];

            Save();
            Status = $"\"{name}\" deleted.";
        }

        private int NextIndex() =>
            _scopes.Count == 0 ? 1 : _scopes.Max(s => s.Index) + 1;

        // --------------------------------------------------------- Validation

        private void Validate()
        {
            if (Selected is null || !IsEditable)
            {
                Problem = string.Empty;
                return;
            }

            Problem = Selected.TryValidate(out string? problem) ? string.Empty : problem ?? string.Empty;
        }
    }
}
