// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Decides which services appear individually in the table column and
    /// which are folded into a "+n".
    /// <para>
    /// By default <b>nothing</b> is folded: a column labelled "Running
    /// services" is read to find out what runs. A fixed limit of three names
    /// would hide the answer behind a "+5" precisely on the devices with the
    /// most services, where there is the most to see.
    /// </para>
    /// <para>
    /// Static on purpose. The column binds directly to <see cref="Device"/>,
    /// and a device carries no reference to the settings - it comes from the
    /// network, not from the user interface. A display option that applies to
    /// the whole window is the one case where this is acceptable.
    /// </para>
    /// </summary>
    public static class ServiceDisplay
    {
        /// <summary>
        /// Folds the selected services. When off, all services are shown
        /// individually.
        /// </summary>
        public static bool GroupSelected { get; set; }

        /// <summary>
        /// The services that are folded, as selected in the settings. Intended
        /// for services that run on nearly every device and therefore do not
        /// distinguish devices.
        /// </summary>
        public static HashSet<string> Grouped { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Folds open TCP ports without a detected service into one "TCP Ports"
        /// chip instead of showing each one as "TCP 8080", "TCP 8443" and so on.
        /// Unlike <see cref="Grouped"/>, this is not a fixed list of names but
        /// every finding of the form "TCP {Port}" - exactly the cases in which a
        /// device with many open ports would otherwise overflow the column. On
        /// by default because this is the case that most often makes the column
        /// unreadable.
        /// </summary>
        public static bool GroupTcpPorts { get; set; } = true;

        /// <summary>The same for UDP ports, see <see cref="GroupTcpPorts"/>.</summary>
        public static bool GroupUdpPorts { get; set; } = true;

        /// <summary>
        /// Raised when the setting changes. The device list subscribes and
        /// redraws the column, because computed properties do not raise change
        /// notifications on their own.
        /// </summary>
        public static event Action? Changed;

        /// <summary>Raises <see cref="Changed"/>.</summary>
        public static void NotifyChanged() => Changed?.Invoke();

        /// <summary>
        /// Splits the service names of a device into "shown individually" and
        /// "counted in the +n".
        /// </summary>
        /// <param name="names">The service names of the device.</param>
        /// <returns>The names to show and the number of folded names.</returns>
        public static (IReadOnlyList<string> Shown, int Folded) Split(IReadOnlyList<string> names)
        {
            if (!GroupSelected || Grouped.Count == 0) return (names, 0);

            List<string> shown = [.. names.Where(n => !Grouped.Contains(n))];

            return (shown, names.Count - shown.Count);
        }
    }
}
