// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// The name under which a service appears in the user interface.
    /// <para>
    /// <c>ServiceType.ToString()</c> returns the source identifier. It works as
    /// a key but not always as information: "S7" only means something to those
    /// who already know the protocol.
    /// </para>
    /// <para>
    /// The mapping table is used instead of renaming enum members on purpose:
    /// the enum name is stored in saved device data and in the scan method
    /// settings; changing it would invalidate both.
    /// </para>
    /// </summary>
    public static class ServiceNames
    {
        /// <summary>Returns the display name of a service.</summary>
        /// <param name="service">The service.</param>
        /// <returns>The display name; the enum name if no special name is defined.</returns>
        public static string Of(ServiceType service) => service switch
        {
            ServiceType.S7 => "S7 PLC (SPS)",
            ServiceType.SecsGem => "SECS/GEM",
            _ => service.ToString()
        };

        /// <summary>
        /// The display name for a stored service name. If the text parses as a
        /// <see cref="ServiceType"/>, its display name applies; otherwise the text
        /// is returned unchanged, for example for summary rows such as "TCP Ports".
        /// </summary>
        /// <param name="rawName">The stored service name.</param>
        /// <returns>The name to display.</returns>
        public static string DisplayFor(string rawName) =>
            Enum.TryParse(rawName, out ServiceType service) ? Of(service) : rawName;

        /// <summary>
        /// The services whose probe returns more than "running", and the heading
        /// under which that information appears in the details. For services not
        /// listed here the protocol stays in the service row and is not moved to
        /// the detail view; otherwise every other service there would only show
        /// the note "response matches the expected protocol".
        /// </summary>
        public static readonly (ServiceType Service, string Label)[] WithDeviceInfo =
        [
            (ServiceType.BacNet, "BACnet device"),
            (ServiceType.ModBus, "Modbus device"),
            (ServiceType.OPCUA,  "OPC UA server"),
            (ServiceType.S7,     "S7 PLC"),
            (ServiceType.Wago,   "WAGO device"),
            (ServiceType.SecsGem, "SECS/GEM equipment"),

            // Services that announce themselves during connection setup. They
            // reveal less than a controller, but software, version and
            // authentication method are known before any login - and for VNC
            // and RDP the authentication method is the finding the search is
            // for.
            (ServiceType.FTP,          "FTP server"),
            (ServiceType.SSH,          "SSH server"),
            (ServiceType.RDP,          "Remote Desktop"),
            (ServiceType.UltraVNC,     "VNC server"),
            (ServiceType.MySQL,        "MySQL server"),
            (ServiceType.MariaDB,      "MariaDB server"),
            (ServiceType.MSSQLServer,  "SQL Server"),
            (ServiceType.PostgreSQL,   "PostgreSQL server"),
            (ServiceType.OracleDB,     "Oracle listener"),
            (ServiceType.MongoDB,      "MongoDB server"),
            (ServiceType.InfluxDB2,    "InfluxDB server")
        ];

        /// <summary>Returns the detail heading for a service.</summary>
        /// <param name="service">The service.</param>
        /// <returns>The heading, or <c>null</c> if the service provides no device information.</returns>
        public static string? InfoLabelOf(ServiceType service)
        {
            foreach ((ServiceType candidate, string label) in WithDeviceInfo)
            {
                if (candidate == service) return label;
            }

            return null;
        }
    }
}
