namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Die Gruppen der Dienstverwaltung, wortgleich zu
    /// <c>ScanningMethod_Services.GetServiceGroup</c>.
    /// <para>
    /// An einer Stelle und nicht in jeder Sondendatei erneut: die Namen tragen
    /// Emoji, und ein danebengegriffenes Zeichen faellt im Quelltext nicht auf -
    /// wohl aber in der Verwaltung, wo der Dienst dann in einer eigenen,
    /// fast gleich heissenden Gruppe steht. Der Vergleich gegen den alten
    /// Schalter prueft sie zeichenweise mit.
    /// </para>
    /// </summary>
    public static class ServiceGroups
    {
        public const string Network = "🌍 Netzwerk-Dienste";
        public const string Remote = "🖥️ Remote-Desktop & Fernwartung";
        public const string SqlDatabases = "🗄️ SQL-Datenbanken";
        public const string NoSqlDatabases = "📦 NoSQL-Datenbanken";
        public const string Industrial = "🏭 Industrieprotokolle";
        public const string Other = "❓ Sonstige";
    }
}
