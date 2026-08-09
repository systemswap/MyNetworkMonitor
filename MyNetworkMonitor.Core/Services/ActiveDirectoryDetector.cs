using System.Net.NetworkInformation;
using DnsClient;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Ob im aktuellen Netz ein Active-Directory-Domänencontroller erreichbar ist -
    /// die einzige plattformübergreifende, protokollbasierte Antwort auf die Frage
    /// "bin ich gerade in einem Firmennetz".
    /// <para>
    /// Fragt DNS nach dem wohlbekannten AD-Dienstsatz
    /// <c>_ldap._tcp.dc._msdcs.&lt;domain&gt;</c> (RFC 2782, von Microsoft für
    /// die DC-Suche festgelegt) - demselben Weg, über den jeder domänengebundene
    /// Windows-Rechner selbst seinen Domain Controller findet. Löst das auf,
    /// steht ein echter DC im Netz; sonst nicht. Das ersetzt die frühere Prüfung
    /// bekannter IP-Bereiche ("10.", "172."): die kommen auf Heimnetzen (Mesh-Router,
    /// Docker, VPN, WSL) genauso vor wie in Firmen und waren nie ein verlässliches
    /// Unterscheidungsmerkmal. Ein auflösbarer DC-SRV-Eintrag dagegen kommt in einem
    /// privaten Netz praktisch nie vor.
    /// </para>
    /// <para>
    /// Bewusst kein Rückgriff auf die Domänenmitgliedschaft des Geräts selbst
    /// (<c>Domain.GetComputerDomain()</c> unter Windows): die beantwortet nur "ist
    /// dieses Gerät jemals einer Domäne beigetreten", nicht "bin ich gerade in
    /// diesem Netz" - ein domänengebundener Laptop im Homeoffice würde damit
    /// dieselbe Fehlmeldung auslösen wie die alte IP-Heuristik, nur aus einem
    /// anderen Grund. Die SRV-Abfrage braucht dagegen eine aktuell erreichbare
    /// Gegenstelle und beantwortet damit die richtige Frage.
    /// </para>
    /// </summary>
    public static class ActiveDirectoryDetector
    {
        /// <summary>
        /// Zeitlimit je Domänen-Kandidat. Kurz gehalten: ein Namensserver, der
        /// diesen Eintrag nicht kennt, antwortet entweder schnell mit NXDOMAIN
        /// oder gar nicht - und "gar nicht" darf den Programmstart nicht spürbar
        /// aufhalten.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1.5);

        /// <summary>
        /// Obergrenze für den gesamten Test, unabhängig davon, wie viele
        /// Domänen-Kandidaten es gibt. Diese Uhr zählt, nicht die Summe der
        /// Einzelzeitlimits - sonst könnten mehrere lahme Namensserver
        /// hintereinander den Start doch wieder verzögern.
        /// </summary>
        private static readonly TimeSpan OverallTimeout = TimeSpan.FromSeconds(2.5);

        /// <summary>
        /// Synchrone Fassade für Aufrufer wie <see cref="IEnterpriseEnvironment"/>,
        /// deren Schnittstelle keine asynchrone Prüfung vorsieht.
        /// <para>
        /// Läuft über <see cref="Task.Run(Func{Task})"/> statt direkt zu warten:
        /// so hat die Prüfung keinen SynchronizationContext, auf den sie am Ende
        /// zurück müsste - genau das hat den früheren Starthänger an der
        /// Webengine verursacht, und dieselbe Falle soll hier nicht wieder
        /// zuschnappen.
        /// </para>
        /// </summary>
        public static bool DomainControllerReachable()
        {
            try
            {
                return Task.Run(() => DomainControllerReachableAsync(CancellationToken.None))
                    .GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // Zeitlimit oder sonst ein Fehler ist kein Firmennetz - und
                // darf den Start erst recht nicht zum Absturz bringen.
                return false;
            }
        }

        public static async Task<bool> DomainControllerReachableAsync(CancellationToken cancellationToken)
        {
            List<string> candidates = [.. CandidateDomains()];
            if (candidates.Count == 0) return false;

            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(OverallTimeout);

            try
            {
                IEnumerable<Task<bool>> lookups = candidates.Select(domain => HasDomainControllerAsync(domain, limit.Token));
                bool[] results = await Task.WhenAll(lookups);
                return results.Any(found => found);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Nur das eigene Zeitlimit abgelaufen, kein Abbruch von aussen -
                // dann ist "kein DC gefunden" die richtige Antwort.
                return false;
            }
        }

        /// <summary>
        /// Eine einzelne SRV-Abfrage. Kein Treffer, kein Server, ein Zeitlimit -
        /// alles zählt gleich als "hier kein Domänencontroller".
        /// </summary>
        private static async Task<bool> HasDomainControllerAsync(string domain, CancellationToken cancellationToken)
        {
            try
            {
                LookupClient client = new(new LookupClientOptions
                {
                    Timeout = QueryTimeout,
                    Retries = 0,
                    UseCache = false,
                    ThrowDnsErrors = false
                });

                using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(QueryTimeout);

                IDnsQueryResponse response = await client.QueryAsync(
                    $"_ldap._tcp.dc._msdcs.{domain}", QueryType.SRV, cancellationToken: cts.Token);

                return !response.HasError && response.Answers.SrvRecords().Any();
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Die Domänennamen, die geprüft werden: die globale DNS-Domäne des
        /// Rechners sowie die DNS-Suffixe aktiver, physischer Adapter. Virtuelle
        /// Adapter (Docker, libvirt, VPN, WSL) fallen heraus - sie tragen keine
        /// vom DHCP zugewiesene Domäne, sondern höchstens einen geerbten oder
        /// leeren Suffix, der die Prüfung nur verlangsamt, nie bestätigt.
        /// </summary>
        private static IEnumerable<string> CandidateDomains()
        {
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            string globalDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrWhiteSpace(globalDomain) && seen.Add(globalDomain))
            {
                yield return globalDomain;
            }

            NetworkInterface[] interfaces;
            try
            {
                interfaces = NetworkInterface.GetAllNetworkInterfaces();
            }
            catch (NetworkInformationException)
            {
                yield break;
            }

            foreach (NetworkInterface nic in interfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (IsVirtualAdapter(nic.Name)) continue;

                string suffix;
                try
                {
                    suffix = nic.GetIPProperties().DnsSuffix;
                }
                catch (NetworkInformationException) { continue; }
                catch (PlatformNotSupportedException) { continue; }

                if (!string.IsNullOrWhiteSpace(suffix) && seen.Add(suffix))
                {
                    yield return suffix;
                }
            }
        }

        /// <summary>
        /// Adapternamen, die nie ein DHCP-zugewiesenes Firmen-Suffix tragen:
        /// Container- und Hypervisor-Brücken, VPN- und Tunnel-Interfaces. Ihr
        /// Vorhandensein war der eigentliche Grund für die Fehlalarme der alten
        /// IP-Heuristik (siehe <c>docker0</c>, das mit <c>172.17.0.1</c> jede
        /// "172."-Prüfung auf jedem Heimrechner mit Docker auslöste).
        /// </summary>
        private static bool IsVirtualAdapter(string name)
        {
            string lower = name.ToLowerInvariant();

            return lower.StartsWith("docker") || lower.StartsWith("veth")
                || lower.StartsWith("virbr") || lower.StartsWith("br-")
                || lower.StartsWith("vmnet") || lower.StartsWith("vboxnet")
                || lower.StartsWith("tun") || lower.StartsWith("tap")
                || lower.StartsWith("wg") || lower.StartsWith("utun")
                || lower.StartsWith("zt");
        }
    }
}
