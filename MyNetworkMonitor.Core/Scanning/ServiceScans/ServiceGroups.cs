// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// The groups of the service manager, used by the probes and by
    /// <c>ScanningMethod_Services.GetServiceGroup</c>.
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
        public const string Network = "🌍 Network services";
        /// <summary>Remote desktop and remote maintenance.</summary>
        public const string Remote = "🖥️ Remote desktop & remote maintenance";
        /// <summary>SQL databases.</summary>
        public const string SqlDatabases = "🗄️ SQL databases";
        /// <summary>NoSQL databases.</summary>
        public const string NoSqlDatabases = "📦 NoSQL databases";
        /// <summary>Industrial protocols.</summary>
        public const string Industrial = "🏭 Industrial protocols";
        /// <summary>Services without a group of their own.</summary>
        public const string Other = "❓ Other";
    }
}
