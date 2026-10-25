// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// A main scanner that this installation connects out to as a satellite,
    /// for example a workstation laptop or a server.
    /// <para>
    /// A satellite knows several of them and keeps a connection to all of them
    /// at the same time, each approved separately and reconnecting
    /// independently (SATELLIT.md, section 1). If one fails, the others keep
    /// working.
    /// </para>
    /// <para>
    /// The counterpart is <see cref="Satellite"/>, which describes who connects
    /// <em>to this installation</em>.
    /// </para>
    /// </summary>
    public partial class MainScanner : ObservableObject
    {
        /// <summary>
        /// Host name or address. A name is preferable - it survives an address
        /// change, which is what makes a laptop usable as a main scanner.
        /// </summary>
        [ObservableProperty] private string _host = string.Empty;

        /// <summary>
        /// The domain appended to a short name; optional.
        /// <para>
        /// Intended for a satellite in a segment where the DNS suffix is not
        /// appended automatically: there "laptop" does not resolve, but
        /// "laptop.corp.example" does. Leave empty where the short name is
        /// sufficient or an address is entered, hence optional.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _domain = string.Empty;

        /// <summary>
        /// The port of this receiver. Set per entry rather than globally: the
        /// same satellite can reach one main scanner on 443 and another on
        /// 27411, which helps where only a few outbound ports are allowed.
        /// </summary>
        [ObservableProperty] private int _port = 27411;

        /// <summary>A note to identify the entry, such as "Office laptop" or "Server".</summary>
        [ObservableProperty] private string _note = string.Empty;

        /// <summary>
        /// Whether to connect to this receiver at all. When off, the entry is
        /// kept but not dialed - for example a laptop that is away for a while.
        /// </summary>
        [ObservableProperty] private bool _enabled = true;

        /// <summary>
        /// The pinned fingerprint of this main scanner. Taken on the first
        /// connection and checked afterwards: a different key is a different
        /// peer, whatever the name (SATELLIT.md, section 4, item 5).
        /// <para>
        /// It is <b>persisted</b>. Held only in memory, it would last until the
        /// next start, after which the satellite would again blindly trust the
        /// first peer to answer - making the whole check worthless.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _pinnedFingerprint = string.Empty;

        // --- Runtime state, none of it is persisted ---------------------------

        /// <summary>Whether the connection to this receiver is currently established.</summary>
        [ObservableProperty] private bool _isConnected;

        /// <summary>Whether this receiver has approved this installation.</summary>
        [ObservableProperty] private bool _isApproved;

        /// <summary>The last message reported by the connection, one sentence for the list.</summary>
        [ObservableProperty] private string _status = "Not connected.";

        /// <summary>A connection is currently being attempted or maintained.</summary>
        [ObservableProperty] private bool _isActive;

        /// <summary>
        /// Connected but not yet approved - the state between "Connect pressed"
        /// and "accepted on the main scanner".
        /// </summary>
        public bool IsWaitingForApproval => IsConnected && !IsApproved;

        partial void OnIsConnectedChanged(bool value) => OnPropertyChanged(nameof(IsWaitingForApproval));
        partial void OnIsApprovedChanged(bool value) => OnPropertyChanged(nameof(IsWaitingForApproval));

        /// <summary>
        /// The name actually connected to: the short name plus domain, if a
        /// domain is set and needed.
        /// <para>
        /// The domain is appended only if <see cref="Host"/> contains neither a
        /// dot nor a colon. An IPv4 address contains dots, an IPv6 address
        /// colons, a fully qualified name dots - in all three cases an appended
        /// suffix would be wrong and the entry would never connect.
        /// </para>
        /// </summary>
        public string TargetHost
        {
            get
            {
                string host = Host?.Trim() ?? string.Empty;
                string domain = Domain?.Trim().TrimStart('.') ?? string.Empty;

                if (domain.Length == 0) return host;
                if (host.Length == 0) return host;
                if (host.Contains('.') || host.Contains(':')) return host;

                return $"{host}.{domain}";
            }
        }

        /// <summary>How the entry is shown in the list.</summary>
        public string Display =>
            string.IsNullOrWhiteSpace(Note)
                ? $"{TargetHost}:{Port}"
                : $"{TargetHost}:{Port}  ({Note})";

        partial void OnHostChanged(string value) => OnTargetChanged();
        partial void OnDomainChanged(string value) => OnTargetChanged();
        partial void OnPortChanged(int value) => OnPropertyChanged(nameof(Display));
        partial void OnNoteChanged(string value) => OnPropertyChanged(nameof(Display));

        private void OnTargetChanged()
        {
            OnPropertyChanged(nameof(TargetHost));
            OnPropertyChanged(nameof(Display));
        }
    }
}
