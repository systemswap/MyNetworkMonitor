namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Ordnet einen Dienst seiner Gruppe zu - dieselbe Gliederung, die das
    /// <c>ServiceType</c>-Enum bereits durch seine Reihenfolge vorgibt.
    /// <para>
    /// Bewusst eine eigene Stelle: die Zuordnung wird nicht nur vom regulaeren
    /// Dienstscan gebraucht, sondern auch von der Portsuche ueber alle Ports.
    /// Stuende sie nur im Scan-Adapter, bekaeme derselbe Dienst je nach
    /// Fundweg eine andere Kategorie - und stuende in der Detailansicht
    /// zweimal untereinander.
    /// </para>
    /// </summary>
    public static class ServiceCategories
    {
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
