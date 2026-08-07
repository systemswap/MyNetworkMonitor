using System.Net;
using DnsClient;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Was ein einzelner Namensserver zu einer Adresse zu sagen hatte.
    /// </summary>
    /// <param name="Server">Der befragte Namensserver.</param>
    /// <param name="HostName">Der Name, den er zur Adresse nennt - leer, wenn keiner.</param>
    /// <param name="Addresses">Die Adressen, die er zu diesem Namen zurueckgibt.</param>
    /// <param name="Error">Womit die Abfrage gescheitert ist, falls sie es tat.</param>
    public sealed record DnsServerAnswer(
        string Server, string HostName, IReadOnlyList<string> Addresses, string Error)
    {
        /// <summary>Der Server hat ueberhaupt nicht geantwortet.</summary>
        public bool Failed => Error.Length > 0;

        /// <summary>Er hat geantwortet, kennt die Adresse aber nicht.</summary>
        public bool IsEmpty => !Failed && HostName.Length == 0;

        /// <summary>
        /// Der Rueckwaertsweg fuehrt zu einem Namen, der Vorwaertsweg aber
        /// nicht zurueck zur Adresse. Das ist der Fall, den man ohne beide
        /// Richtungen nie sieht.
        /// </summary>
        public bool RoundTripBroken { get; init; }

        public string Text =>
            Failed ? $"{Server}: no answer ({Error})"
            : IsEmpty ? $"{Server}: does not know this address"
            : RoundTripBroken
                ? $"{Server}: {HostName}, but the name points back to " +
                  (Addresses.Count == 0 ? "nothing" : string.Join(", ", Addresses))
                : $"{Server}: {HostName}";
    }

    /// <summary>
    /// Das Ergebnis eines Quervergleichs ueber alle Namensserver.
    /// </summary>
    public sealed record DnsCrossCheckResult(
        string Address, IReadOnlyList<DnsServerAnswer> Answers)
    {
        /// <summary>
        /// Die Namen, auf die sich die antwortenden Server geeinigt haben.
        /// Mehr als einer heisst: sie widersprechen sich.
        /// </summary>
        public IReadOnlyList<string> DistinctNames =>
            [.. Answers.Where(a => !a.Failed && !a.IsEmpty)
                       .Select(a => a.HostName)
                       .Distinct(StringComparer.OrdinalIgnoreCase)
                       .Order(StringComparer.OrdinalIgnoreCase)];

        /// <summary>Server, die geantwortet, die Adresse aber nicht gekannt haben.</summary>
        public IReadOnlyList<DnsServerAnswer> Silent => [.. Answers.Where(a => a.IsEmpty)];

        /// <summary>Server, die gar nicht erreichbar waren.</summary>
        public IReadOnlyList<DnsServerAnswer> Unreachable => [.. Answers.Where(a => a.Failed)];

        /// <summary>Server, bei denen der Rueckweg nicht zur Adresse zurueckfuehrt.</summary>
        public IReadOnlyList<DnsServerAnswer> Broken => [.. Answers.Where(a => a.RoundTripBroken)];

        /// <summary>
        /// Es gibt etwas zu melden. Nicht jede Ungleichheit zaehlt: kennt
        /// <em>kein</em> Server die Adresse, ist das kein Widerspruch zwischen
        /// ihnen, sondern schlicht ein fehlender Eintrag - und in einem
        /// Heimnetz der Normalfall.
        /// </summary>
        public bool HasMismatch =>
            DistinctNames.Count > 1
            || Broken.Count > 0
            || Unreachable.Count > 0
            || (DistinctNames.Count == 1 && Silent.Count > 0);

        /// <summary>Der Befund in einem Satz - fuer die Findings-Liste.</summary>
        public string Summary
        {
            get
            {
                if (DistinctNames.Count > 1)
                {
                    return "The DNS servers disagree: " +
                           string.Join("; ", Answers.Where(a => !a.Failed && !a.IsEmpty)
                                                    .Select(a => $"{a.Server} says {a.HostName}"));
                }

                List<string> parts = [];

                if (DistinctNames.Count == 1 && Silent.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Silent.Select(a => a.Server))} " +
                              $"{(Silent.Count == 1 ? "does" : "do")} not know the address, " +
                              $"while the others resolve it to {DistinctNames[0]}");
                }

                if (Broken.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Broken.Select(a => a.Server))} " +
                              "returns a name that does not point back to this address");
                }

                if (Unreachable.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Unreachable.Select(a => a.Server))} " +
                              $"did not answer at all");
                }

                return parts.Count == 0
                    ? "All DNS servers agree."
                    : string.Join(". ", parts) + ".";
            }
        }

        /// <summary>Alle Antworten untereinander - fuer das Detailpanel.</summary>
        public string Report => string.Join("\r\n", Answers.Select(a => a.Text));
    }

    /// <summary>
    /// Fragt dieselbe Adresse bei jedem bekannten Namensserver einzeln nach und
    /// stellt die Antworten nebeneinander.
    /// <para>
    /// Der Sinn ist die Fehlersuche: solange alle Server dasselbe sagen, ist
    /// nichts zu tun. Weichen sie ab, <b>ist genau das der Befund</b> - und
    /// weil jede Antwort ihren Server mitfuehrt, steht auch da, welcher von
    /// ihnen nicht sauber aufloest.
    /// </para>
    /// <para>
    /// Geprueft werden <b>beide Richtungen</b>. Der Rueckwaertsweg allein
    /// uebersieht den Fall, in dem alle Server denselben Namen liefern, dieser
    /// Name aber auf eine andere Adresse zurueckzeigt - ein veralteter
    /// Vorwaertseintrag, der einzeln betrachtet auf jedem Server richtig
    /// aussieht.
    /// </para>
    /// </summary>
    public static class DnsCrossCheck
    {
        /// <summary>
        /// Wie lange auf einen einzelnen Server gewartet wird. Kurz gehalten:
        /// die Abfragen laufen ueber mehrere Server, und ein stummer Server
        /// darf den Vergleich nicht aufhalten - dass er stumm ist, ist selbst
        /// die Antwort.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(2);

        /// <summary>
        /// Vergleicht eine Adresse ueber die angegebenen Namensserver. Sind
        /// keine angegeben, werden die des Systems genommen.
        /// </summary>
        public static async Task<DnsCrossCheckResult> RunAsync(
            string address, IReadOnlyList<string> servers, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(address);

            List<IPAddress> resolvers = [.. servers
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(s => IPAddress.TryParse(s, out IPAddress? parsed) ? parsed : null)
                .Where(a => a is not null)
                .Select(a => a!)];

            if (resolvers.Count == 0) resolvers = [.. SystemResolvers()];

            if (resolvers.Count == 0)
            {
                return new DnsCrossCheckResult(address, []);
            }

            // Die Server parallel fragen. Nacheinander summieren sich die
            // Zeitlimits: fuenf stumme Server sind dann zehn Sekunden, in
            // denen die Oberflaeche steht.
            DnsServerAnswer[] answers = await Task.WhenAll(
                resolvers.Select(server => AskAsync(address, server, cancellationToken)));

            return new DnsCrossCheckResult(address, answers);
        }

        /// <summary>Dieselbe Pruefung fuer mehrere Adressen nacheinander.</summary>
        public static async Task<List<DnsCrossCheckResult>> RunAsync(
            IEnumerable<string> addresses, IReadOnlyList<string> servers,
            CancellationToken cancellationToken = default)
        {
            List<DnsCrossCheckResult> results = [];

            foreach (string address in addresses)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(await RunAsync(address, servers, cancellationToken));
            }

            return results;
        }

        /// <summary>
        /// Ein Server, beide Richtungen. Erst die Adresse zum Namen, dann den
        /// Namen zurueck zu den Adressen - und beides bei demselben Server,
        /// sonst vergliche man zwei verschiedene Auskuenfte miteinander.
        /// </summary>
        private static async Task<DnsServerAnswer> AskAsync(
            string address, IPAddress server, CancellationToken cancellationToken)
        {
            string text = server.ToString();

            try
            {
                LookupClient client = new(new LookupClientOptions(new NameServer(server))
                {
                    Timeout = QueryTimeout,
                    Retries = 1,

                    // Jeder Server bekommt seine eigene Frage. Ein Treffer aus
                    // dem Zwischenspeicher waere hier das Gegenteil dessen, was
                    // geprueft werden soll.
                    UseCache = false,

                    // Ein fehlender Eintrag ist eine Antwort, kein Fehler.
                    ThrowDnsErrors = false
                });

                using CancellationTokenSource cts =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(QueryTimeout);

                IPHostEntry? reverse = await client.GetHostEntryAsync(address).WaitAsync(cts.Token);

                string hostName = reverse?.HostName ?? string.Empty;
                if (hostName.Length == 0)
                {
                    return new DnsServerAnswer(text, string.Empty, [], string.Empty);
                }

                // Der Rueckweg: zeigt der Name wieder auf diese Adresse?
                IPHostEntry? forward = await client.GetHostEntryAsync(hostName).WaitAsync(cts.Token);

                List<string> addresses = [.. (forward?.AddressList ?? [])
                    .Select(a => a.ToString())
                    .Distinct(StringComparer.OrdinalIgnoreCase)];

                bool pointsBack = addresses.Any(a =>
                    string.Equals(a, address, StringComparison.OrdinalIgnoreCase));

                return new DnsServerAnswer(text, hostName, addresses, string.Empty)
                {
                    RoundTripBroken = !pointsBack
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Ein Server, der nicht antwortet, ist ein Befund und kein
                // Grund, den Vergleich der uebrigen fallen zu lassen.
                return new DnsServerAnswer(text, string.Empty, [], Short(ex.Message));
            }
        }

        /// <summary>Die Namensserver, die der Rechner selbst benutzt.</summary>
        private static IEnumerable<IPAddress> SystemResolvers()
        {
            try
            {
                // NameServer.Address ist die Adresse als Text - fuer die
                // Abfrage wird sie wieder als Adresse gebraucht.
                return NameServer.ResolveNameServers()
                    .Select(n => n.Address)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(a => IPAddress.TryParse(a, out IPAddress? parsed) ? parsed : null)
                    .Where(a => a is not null)
                    .Select(a => a!);
            }
            catch (Exception)
            {
                return [];
            }
        }

        /// <summary>
        /// Fehlermeldungen der Bibliothek sind mehrzeilig. In einer Tabelle
        /// zerreisst das die Zeile, ohne mehr zu sagen als der erste Satz.
        /// </summary>
        private static string Short(string message)
        {
            string first = message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                                  .FirstOrDefault() ?? "timeout";

            return first.Length > 90 ? first[..90] + "..." : first;
        }
    }
}
