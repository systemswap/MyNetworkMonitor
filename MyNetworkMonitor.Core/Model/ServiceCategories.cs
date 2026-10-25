namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Assigns a service to its group, following the same structure that the
    /// order of the <c>ServiceType</c> enum already defines.
    /// <para>
    /// Kept in one place on purpose: both the regular service scan and the
    /// all-ports search need the assignment. If it lived only in the scan
    /// adapter, the same service would get a different category depending on
    /// how it was found and would appear twice in the detail view.
    /// </para>
    /// </summary>
    public static class ServiceCategories
    {
        /// <summary>Returns the category name of a service.</summary>
        /// <param name="service">The service to classify.</param>
        /// <returns>"Network", "Remote", "Databases" or "Other".</returns>
        public static string Of(ServiceType service) => service switch
        {
            ServiceType.WebServices or ServiceType.DNS_TCP or ServiceType.DNS_UDP
                or ServiceType.DHCP or ServiceType.SSH or ServiceType.FTP => "Network",

            ServiceType.RDP or ServiceType.UltraVNC or ServiceType.BigFixRemote
                or ServiceType.TeamViewer or ServiceType.Anydesk
                or ServiceType.RustdeskServer or ServiceType.RustdeskClient => "Remote",

            ServiceType.MSSQLServer or ServiceType.PostgreSQL or ServiceType.MariaDB
                or ServiceType.MySQL or ServiceType.OracleDB or ServiceType.MongoDB
                or ServiceType.InfluxDB2 => "Databases",

            _ => "Other"
        };
    }
}
