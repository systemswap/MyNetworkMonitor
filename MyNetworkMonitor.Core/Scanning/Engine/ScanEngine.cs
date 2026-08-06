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
                List<ScopeRuntime> scopes = BuildScopeRuntimes(selectedScopes);
                List<ScanTargetEntry> targets = BuildTargets(scopes);

                HashSet<string> wanted = new(selectedMethodIds, StringComparer.OrdinalIgnoreCase);

                foreach (ScanPhase phase in Enum.GetValues<ScanPhase>().OrderBy(p => (int)p))
                {
                    foreach (IScanMethod method in _methods.Where(m => m.Phase == phase && wanted.Contains(m.Id)))
                    {
                        if (_cts.IsCancellationRequested) break;

                        ScanMethodOutcome outcome = await RunOneAsync(method, scopes, targets, settings, store, _cts.Token);
                        outcomes.Add(outcome);
                        MethodFinished?.Invoke(outcome);
                    }

                    if (_cts.IsCancellationRequested) break;
                }

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

        // ----------------------------------------------------------- Aufbau

        /// <summary>
        /// Ordnet jedem Bereich seinen Adapter und dessen IPv6-Zustand zu.
        /// Geschieht einmal je Durchlauf, nicht je Verfahren.
        /// </summary>
        private static List<ScopeRuntime> BuildScopeRuntimes(IEnumerable<ScanScope> scopes)
        {
            NetworkInterface[] all = NetworkInterface.GetAllNetworkInterfaces();
            List<ScopeRuntime> result = [];

            foreach (ScanScope scope in scopes.OrderBy(s => s.Index))
            {
                NetworkInterface? nic = null;

                if (!string.IsNullOrWhiteSpace(scope.InterfaceId))
                {
                    nic = all.FirstOrDefault(n => n.Id == scope.InterfaceId);
                }

                // Bereiche ohne festen Adapter laufen ueber den Adapter, ueber
                // den das Betriebssystem sie ohnehin routen wuerde. Bis die
                // Routenwahl steht, dient der erste betriebsbereite Adapter
                // als Naeherung.
                nic ??= all.FirstOrDefault(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                result.Add(new ScopeRuntime
                {
                    Scope = scope,
                    Interface = nic,
                    Ipv6 = Ipv6Readiness.ForInterface(nic)
                });
            }

            return result;
        }

        /// <summary>
        /// Loest die Bereiche in einzelne Ziele auf. Ein IPv6-Praefix liefert
        /// hier bewusst keine Ziele - es wird nicht durchlaufen, sondern von
        /// den IPv6-Verfahren selbst untersucht, die dazu den Bereich aus
        /// <see cref="ScanContext.Scopes"/> heranziehen.
        /// </summary>
        private static List<ScanTargetEntry> BuildTargets(List<ScopeRuntime> scopes)
        {
            List<ScanTargetEntry> targets = [];

            foreach (ScopeRuntime runtime in scopes)
            {
                switch (runtime.Scope.Kind)
                {
                    case ScanScopeKind.IPv4Range:
                        foreach (System.Net.IPAddress address in runtime.Scope.EnumerateIPv4Range())
                        {
                            targets.Add(new ScanTargetEntry
                            {
                                Address = IpAddressAnalyzer.Analyze(address),
                                Scope = runtime
                            });
                        }
                        break;

                    case ScanScopeKind.TargetList:
                        (List<IpAddressInfo> addresses, List<string> hostnames) = runtime.Scope.SplitTargetList();

                        foreach (IpAddressInfo info in addresses)
                        {
                            targets.Add(new ScanTargetEntry { Address = info, Scope = runtime });
                        }
                        foreach (string host in hostnames)
                        {
                            targets.Add(new ScanTargetEntry { HostName = host, Scope = runtime });
                        }
                        break;

                    case ScanScopeKind.NetworkInterface:
                        targets.AddRange(BuildInterfaceTargets(runtime));
                        break;

                    case ScanScopeKind.IPv6Prefix:
                        // Absichtlich leer - siehe Hinweis am Methodenkopf.
                        break;
                }
            }

            return targets;
        }

        /// <summary>
        /// Leitet aus einem Adapter das IPv4-Subnetz ab und zaehlt es auf.
        /// Die IPv6-Seite steuern die IPv6-Verfahren selbst bei - ein /64
        /// laesst sich nicht aufzaehlen.
        /// </summary>
        private static IEnumerable<ScanTargetEntry> BuildInterfaceTargets(ScopeRuntime runtime)
        {
            if (runtime.Interface is null) yield break;

            foreach (UnicastIPAddressInformation unicast in runtime.Interface.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                if (unicast.IPv4Mask is null) continue;

                uint address = ToUInt32(unicast.Address);
                uint mask = ToUInt32(unicast.IPv4Mask);
                if (mask == 0) continue;

                uint network = address & mask;
                uint broadcast = network | ~mask;

                // Netz- und Broadcast-Adresse sind keine Ziele. Bei einem /31
                // oder /32 bleibt nichts uebrig.
                if (broadcast <= network + 1) continue;

                for (uint value = network + 1; value < broadcast; value++)
                {
                    yield return new ScanTargetEntry
                    {
                        Address = IpAddressAnalyzer.Analyze(FromUInt32(value)),
                        Scope = runtime
                    };
                }
            }
        }

        private static uint ToUInt32(System.Net.IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static System.Net.IPAddress FromUInt32(uint value) => new(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }
}
