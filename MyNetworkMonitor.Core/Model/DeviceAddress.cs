// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// An address of a device, together with everything that does not follow
    /// from the address itself: state, lifetimes and when it was last seen.
    /// <para>
    /// The time reference is essential for IPv6. Addresses with privacy
    /// extensions (RFC 8981) change daily - without <see cref="FirstSeen"/> and
    /// <see cref="LastSeen"/> a mobile phone would count as seven devices over
    /// a week.
    /// </para>
    /// </summary>
    public partial class DeviceAddress : ObservableObject
    {
        /// <summary>The parsed address.</summary>
        public required IpAddressInfo Info { get; init; }

        /// <summary>How the address was assigned to the interface, as reported by the operating system, not guessed.</summary>
        [ObservableProperty] private AddressOrigin _origin = AddressOrigin.Unknown;

        [ObservableProperty] private AddressState _state = AddressState.Unknown;

        /// <summary>
        /// When the address stops being valid, taken from the valid lifetime of
        /// the router advertisement or the DHCP lease. <c>null</c> if unlimited
        /// or unknown.
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _validUntil;

        /// <summary>
        /// When the address becomes usable only for existing connections
        /// (preferred lifetime). Lies before <see cref="ValidUntil"/>.
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _preferredUntil;

        [ObservableProperty] private DateTimeOffset _firstSeen;
        [ObservableProperty] private DateTimeOffset _lastSeen;

        /// <summary>The scan method that reported the address.</summary>
        [ObservableProperty] private string _discoveredBy = string.Empty;

        /// <summary>
        /// The address has responded since it was last checked. Separate from
        /// <see cref="LastSeen"/> because an address can also be observed
        /// passively without being contacted.
        /// </summary>
        [ObservableProperty] private bool _isResponding;

        /// <summary>Expired according to its lifetime, regardless of whether it is still in use.</summary>
        public bool IsExpired => ValidUntil is { } until && until <= DateTimeOffset.Now;

        /// <summary>
        /// Remaining validity as a fraction between 0 and 1, for the progress
        /// bar in the user interface. <c>null</c> for an unlimited lifetime.
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
