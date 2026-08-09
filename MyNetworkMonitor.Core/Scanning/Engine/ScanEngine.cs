using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>Was mit einem Verfahren in einem Durchlauf geschehen ist.</summary>
    public sealed class ScanMethodOutcome
    {
        public required string MethodId { get; init; }
        public required string MethodName { get; init; }
        public required ScanPhase Phase { get; init; }
        public required ScanMethodState State { get; init; }

        /// <summary>Begruendung bei Ueberspringen oder Fehlschlag.</summary>
        public string Reason { get; init; } = string.Empty;

        public TimeSpan Duration { get; init; }

        /// <summary>Ausnahme, falls das Verfahren gescheitert ist.</summary>
        public Exception? Error { get; init; }

        public bool Ran => State == ScanMethodState.Available && Error is null;

        public override string ToString() =>
            $"{MethodName}: {State}{(Reason.Length > 0 ? $" - {Reason}" : "")}";
    }

    /// <summary>Ergebnis eines gesamten Durchlaufs.</summary>
    public sealed class ScanRunResult
    {
        public required IReadOnlyList<ScanMethodOutcome> Outcomes { get; init; }
        public required int TargetCount { get; init; }

        /// <summary>
        /// Wie viele Geraete eine Doppelbelegung tragen.
        /// <para>
        /// Wird vom Aufrufer nachgetragen, nicht von der Engine gefuellt: die
        /// Auswertung schreibt <see cref="Model.Device.Conflicts"/>, und das ist
        /// eine gebundene Eigenschaft. Der Lauf selbst findet im Thread-Pool
        /// statt - von dort aus geschrieben, faellt die Oberflaeche beim
        /// naechsten Zeichnen um.
        /// </para>
        /// </summary>
        public int ConflictCount { get; set; }

        public required TimeSpan Duration { get; init; }
        public required bool WasCancelled { get; init; }

        public IEnumerable<ScanMethodOutcome> Skipped =>
            Outcomes.Where(o => o.State != ScanMethodState.Available);

        public IEnumerable<ScanMethodOutcome> Failed =>
            Outcomes.Where(o => o.Error is not null);
    }

    /// <summary>
    /// Fuehrt Scan-Verfahren aus. Loest die Orchestrierung aus dem Hauptfenster
    /// heraus - dort lagen bisher gut 1.200 Zeilen, die jedes Modul einzeln
    /// verdrahtet haben.
    /// <para>
    /// Die Engine kennt nur <see cref="IScanMethod"/>. Ein IPv6-Verfahren
    /// hinzuzufuegen heisst darum: registrieren. An der Engine aendert sich
    /// nichts.
    /// </para>
    /// </summary>
    public sealed class ScanEngine
    {
        private readonly List<IScanMethod> _methods = [];
        private readonly Lock _reportLock = new();

        private CancellationTokenSource? _cts;

        /// <summary>Alle registrierten Verfahren, in Ausfuehrungsfolge.</summary>
        public IReadOnlyList<IScanMethod> Methods =>
            _methods.OrderBy(m => (int)m.Phase).ToList();

        public bool IsRunning => _cts is not null;

        // ------------------------------------------------------------ Meldungen

        public event Action<ScanProgress>? ProgressChanged;
        public event Action<IScanMethod>? MethodStarted;
        public event Action<ScanMethodOutcome>? MethodFinished;
        public event Action<ScanRunResult>? RunFinished;

        // ---------------------------------------------------------- Registrierung

        /// <summary>
        /// Nimmt ein Verfahren auf. Ein bereits vorhandener
        /// <see cref="IScanMethod.Id"/> wird abgelehnt - doppelte Schluessel
        /// wuerden die gespeicherte Auswahl mehrdeutig machen.
        /// </summary>
        public void Register(IScanMethod method)
        {
            ArgumentNullException.ThrowIfNull(method);

            if (_methods.Any(m => string.Equals(m.Id, method.Id, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"Ein Verfahren mit der Kennung \"{method.Id}\" ist bereits registriert.");
            }

            _methods.Add(method);
        }

        public IScanMethod? Find(string id) =>
            _methods.FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));

        // ------------------------------------------------------------- Abbruch

        /// <summary>
        /// Bricht den laufenden Durchlauf ab. Die Verfahren beenden sich ueber
        /// den Token; Adapter bestehender Module rufen darauf hin deren
        /// <c>StopScan()</c> auf.
        /// </summary>
        public void Stop() => _cts?.Cancel();

        // ---------------------------------------------------------------- Lauf

        /// <summary>
        /// Fuehrt die gewaehlten Verfahren ueber die gewaehlten Bereiche aus.
        /// Die Stufen laufen nacheinander - erst finden, dann bestimmen, dann
        /// Dienste - und innerhalb einer Stufe ebenfalls nacheinander, weil die
        /// Module sich Netzwerkressourcen und Zeitlimits teilen. Nebenlaeufig
        /// wuerden sie sich gegenseitig die Antwortzeiten verderben.
        /// </summary>
        public async Task<ScanRunResult> RunAsync(
            IEnumerable<ScanScope> selectedScopes,
            IEnumerable<string> selectedMethodIds,
            ScanSettings settings,
            DeviceStore store,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(selectedScopes);
            ArgumentNullException.ThrowIfNull(selectedMethodIds);
            ArgumentNullException.ThrowIfNull(settings);
            ArgumentNullException.ThrowIfNull(store);

            if (IsRunning)
            {
                throw new InvalidOperationException("Es laeuft bereits ein Scan. Erst Stop aufrufen.");
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            DateTimeOffset started = DateTimeOffset.Now;
            List<ScanMethodOutcome> outcomes = [];

            try
            {
                List<ScopeRuntime> scopes = ScopeRuntimeFactory.Build(selectedScopes);
                List<ScanTargetEntry> targets = ScopeRuntimeFactory.BuildTargets(scopes);

                if (settings.ClearArpCacheFirst) FlushArpCache();

                HashSet<string> wanted = new(selectedMethodIds, StringComparer.OrdinalIgnoreCase);

                foreach (ScanPhase phase in Enum.GetValues<ScanPhase>().OrderBy(p => (int)p))
                {
                    foreach (IScanMethod method in _methods.Where(m => m.Phase == phase && wanted.Contains(m.Id)))
                    {
                        if (_cts.IsCancellationRequested) break;

                        // Erst hier kuerzen, nicht einmal vor dem Lauf: bis das
                        // Verfahren an der Reihe ist, haben die vorherigen
                        // schon Geraete gefunden, und genau die soll es
                        // abfragen.
                        List<ScanTargetEntry> forMethod = settings.IsRestrictedToKnown(method.Id)
                            ? KeepKnown(targets, store)
                            : targets;

                        ScanMethodOutcome outcome = await RunOneAsync(method, scopes, forMethod, settings, store, _cts.Token);
                        outcomes.Add(outcome);
                        MethodFinished?.Invoke(outcome);
                    }

                    if (_cts.IsCancellationRequested) break;
                }

                // Die Suche nach Doppelbelegungen steht bewusst *nicht* hier.
                //
                // Sie gehoert ans Ende des Laufs - waehrenddessen waere jeder
                // Befund vorlaeufig, weil das zweite Geraet mit derselben
                // Adresse noch kommen kann. Sie schreibt dabei aber
                // Device.Conflicts und Device.ConflictDetails, und beide sind
                // gebunden. Dieser Lauf findet im Thread-Pool statt; von dort
                // aus geschrieben, riss es die Oberflaeche mit. Darum ruft der
                // Aufrufer DuplicateDetector.Analyze selbst auf, sobald er
                // wieder auf seinem Thread ist, und traegt die Zahl nach.
                ScanRunResult result = new()
                {
                    Outcomes = outcomes,
                    TargetCount = targets.Count,
                    Duration = DateTimeOffset.Now - started,
                    WasCancelled = _cts.IsCancellationRequested
                };

                RunFinished?.Invoke(result);
                return result;
            }
            finally
            {
                _cts.Dispose();
                _cts = null;
            }
        }

        /// <summary>
        /// Leert den ARP-Cache des Systems. Ein Fehlschlag ist kein Grund, den
        /// Lauf abzubrechen - ohne erhoehte Rechte geht es schlicht nicht, und
        /// der Scan liefert dann eben die zwischengespeicherten Zuordnungen.
        /// </summary>
        private static void FlushArpCache()
        {
            try { Services.PlatformServices.ArpOrNull?.FlushArpCache(); }
            catch (Exception) { /* siehe oben */ }
        }

        /// <summary>
        /// Reduziert die Ziele auf die bereits bekannten Geraete. Aus einem
        /// Lauf ueber ein ganzes /24 wird damit ein Nachfassen bei den wenigen
        /// Adressen, die tatsaechlich belegt sind - der uebliche zweite und
        /// dritte Durchgang.
        /// <para>
        /// Hostnamen bleiben in jedem Fall stehen: ob sie zu einem bekannten
        /// Geraet gehoeren, weiss man erst nach dem Aufloesen.
        /// </para>
        /// </summary>
        private static List<ScanTargetEntry> KeepKnown(List<ScanTargetEntry> targets, DeviceStore store)
        {
            lock (store.SyncRoot)
            {
                return
                [
                    .. targets.Where(t => t.Address is null || store.FindByAddress(t.Address) is not null)
                ];
            }
        }

        private async Task<ScanMethodOutcome> RunOneAsync(
            IScanMethod method,
            List<ScopeRuntime> scopes,
            List<ScanTargetEntry> targets,
            ScanSettings settings,
            DeviceStore store,
            CancellationToken token)
        {
            DateTimeOffset started = DateTimeOffset.Now;

            ScanContext context = new()
            {
                Scopes = scopes,
                Targets = targets,
                Settings = settings,
                Store = store,
                Report = observation =>
                {
                    // Die Module melden aus beliebigen Aufgaben heraus. Der
                    // Store ist nicht threadsicher, darum hier serialisieren.
                    lock (_reportLock)
                    {
                        store.Observe(observation);
                    }
                },
                ReportProgress = (current, responded, total) =>
                    ProgressChanged?.Invoke(new ScanProgress
                    {
                        MethodId = method.Id,
                        MethodName = method.DisplayName,
                        Phase = method.Phase,
                        Current = current,
                        Responded = responded,
                        Total = total
                    })
            };

            ScanMethodAvailability availability = method.CheckAvailability(context);
            if (!availability.CanRun)
            {
                return new ScanMethodOutcome
                {
                    MethodId = method.Id,
                    MethodName = method.DisplayName,
                    Phase = method.Phase,
                    State = availability.State,
                    Reason = availability.Reason,
                    Duration = TimeSpan.Zero
                };
            }

            MethodStarted?.Invoke(method);

            try
            {
                await method.ExecuteAsync(context, token);

                return new ScanMethodOutcome
                {
                    MethodId = method.Id,
                    MethodName = method.DisplayName,
                    Phase = method.Phase,
                    State = ScanMethodState.Available,
                    Duration = DateTimeOffset.Now - started
                };
            }
            catch (OperationCanceledException)
            {
                return new ScanMethodOutcome
                {
                    MethodId = method.Id,
                    MethodName = method.DisplayName,
                    Phase = method.Phase,
                    State = ScanMethodState.Available,
                    Reason = "abgebrochen",
                    Duration = DateTimeOffset.Now - started
                };
            }
            catch (Exception ex)
            {
                // Ein gescheitertes Verfahren darf den Durchlauf nicht beenden -
                // die uebrigen liefern weiterhin Ergebnisse.
                return new ScanMethodOutcome
                {
                    MethodId = method.Id,
                    MethodName = method.DisplayName,
                    Phase = method.Phase,
                    State = ScanMethodState.Blocked,
                    Reason = ex.Message,
                    Duration = DateTimeOffset.Now - started,
                    Error = ex
                };
            }
        }
    }
}
