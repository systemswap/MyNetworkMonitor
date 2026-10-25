// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// The groups of the service manager; the texts must match
    /// <c>ScanningMethod_Services.GetServiceGroup</c> character for character.
    /// <para>
    /// Defined once rather than in every probe file: the names contain emoji,
    /// and a wrong character goes unnoticed in the source but not in the
    /// service manager, where the service then appears in a separate group
    /// with an almost identical name.
    /// </para>
    /// </summary>
    public static class ServiceGroups
    {
        /// <summary>Network services: web, DNS, DHCP, SSH, FTP.</summary>
        public const string Network = "🌍 Netzwerk-Dienste";
        /// <summary>Remote desktop and remote maintenance.</summary>
        public const string Remote = "🖥️ Remote-Desktop & Fernwartung";
        /// <summary>SQL databases.</summary>
        public const string SqlDatabases = "🗄️ SQL-Datenbanken";
        /// <summary>NoSQL databases.</summary>
        public const string NoSqlDatabases = "📦 NoSQL-Datenbanken";
        /// <summary>Industrial protocols.</summary>
        public const string Industrial = "🏭 Industrieprotokolle";
        /// <summary>Services without a group of their own.</summary>
        public const string Other = "❓ Sonstige";
    }
}
