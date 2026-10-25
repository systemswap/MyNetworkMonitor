// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>Outcome of a single scan method within a run.</summary>
    public sealed class ScanMethodOutcome
    {
        /// <summary>Identifier of the method (<see cref="IScanMethod.Id"/>).</summary>
        public required string MethodId { get; init; }
        /// <summary>Display name of the method.</summary>
        public required string MethodName { get; init; }

        /// <summary>Phase the method belongs to.</summary>
        public required ScanPhase Phase { get; init; }

        /// <summary>Availability state the method had when the run reached it.</summary>
        public required ScanMethodState State { get; init; }

        /// <summary>Reason for skipping or failure; empty when the method ran normally.</summary>
        public string Reason { get; init; } = string.Empty;

        /// <summary>Time the method took.</summary>
        public TimeSpan Duration { get; init; }

        /// <summary>Exception thrown by the method, if it failed.</summary>
        public Exception? Error { get; init; }

        /// <summary>True if the method was available and completed without an exception.</summary>
        public bool Ran => State == ScanMethodState.Available && Error is null;

        /// <inheritdoc />
        public override string ToString() =>
            $"{MethodName}: {State}{(Reason.Length > 0 ? $" - {Reason}" : "")}";
    }

    /// <summary>Result of a complete scan run.</summary>
    public sealed class ScanRunResult
    {
        /// <summary>Outcome of every method the run reached, in execution order.</summary>
        public required IReadOnlyList<ScanMethodOutcome> Outcomes { get; init; }

        /// <summary>Number of targets built from the selected scopes.</summary>
        public required int TargetCount { get; init; }

        /// <summary>
        /// Number of devices that carry an address conflict.
        /// <para>
        /// Set by the caller, not by the engine: the analysis writes
        /// <see cref="Model.Device.Conflicts"/>, which is a bound property. The
        /// run itself executes on the thread pool; written from there, the UI
        /// crashes on its next render pass.
        /// </para>
        /// </summary>
        public int ConflictCount { get; set; }

        /// <summary>Total duration of the run.</summary>
        public required TimeSpan Duration { get; init; }

        /// <summary>True if the run was cancelled before all methods finished.</summary>
        public required bool WasCancelled { get; init; }

        /// <summary>Outcomes of methods that did not run because they were unavailable.</summary>
        public IEnumerable<ScanMethodOutcome> Skipped =>
            Outcomes.Where(o => o.State != ScanMethodState.Available);

        /// <summary>Outcomes of methods that threw an exception.</summary>
        public IEnumerable<ScanMethodOutcome> Failed =>
            Outcomes.Where(o => o.Error is not null);
    }

    /// <summary>
    /// Runs scan methods. Keeps the orchestration of all scan modules out of the
    /// main window.
    /// <para>
    /// The engine only knows <see cref="IScanMethod"/>. Adding a method (such as
    /// an IPv6 method) means registering it; the engine itself does not change.
    /// </para>
    /// </summary>
    public sealed class ScanEngine
    {
        private readonly List<IScanMethod> _methods = [];
        private readonly Lock _reportLock = new();

        private CancellationTokenSource? _cts;

        /// <summary>All registered methods, in execution order.</summary>
        public IReadOnlyList<IScanMethod> Methods =>
            _methods.OrderBy(m => (int)m.Phase).ToList();

        /// <summary>True while a run is in progress.</summary>
        public bool IsRunning => _cts is not null;

        // ------------------------------------------------------------ Events

        /// <summary>Raised when a method reports progress. Raised on a worker thread.</summary>
        public event Action<ScanProgress>? ProgressChanged;

        /// <summary>Raised when a method starts executing.</summary>
        public event Action<IScanMethod>? MethodStarted;

        /// <summary>Raised when a method has finished or was skipped.</summary>
        public event Action<ScanMethodOutcome>? MethodFinished;

        /// <summary>Raised once at the end of a run.</summary>
        public event Action<ScanRunResult>? RunFinished;

        // ---------------------------------------------------------- Registration

        /// <summary>
        /// Registers a method. An already registered
        /// <see cref="IScanMethod.Id"/> is rejected; duplicate keys would make
        /// the saved selection ambiguous.
        /// </summary>
        /// <param name="method">The method to add.</param>
        /// <exception cref="ArgumentNullException"><paramref name="method"/> is null.</exception>
        /// <exception cref="InvalidOperationException">A method with the same identifier is already registered.</exception>
        public void Register(IScanMethod method)
        {
            ArgumentNullException.ThrowIfNull(method);

            if (_methods.Any(m => string.Equals(m.Id, method.Id, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"A method with the ID \"{method.Id}\" is already registered.");
            }

            _methods.Add(method);
        }

        /// <summary>Looks up a registered method by identifier (case-insensitive).</summary>
        /// <param name="id">The method identifier.</param>
        /// <returns>The method, or null if none is registered under <paramref name="id"/>.</returns>
        public IScanMethod? Find(string id) =>
            _methods.FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));

        // ------------------------------------------------------------- Cancellation

        /// <summary>
        /// Cancels the current run. Methods end via the cancellation token;
        /// adapters around scan modules then call the module's
        /// <c>StopScan()</c>.
        /// </summary>
        public void Stop() => _cts?.Cancel();

        // ---------------------------------------------------------------- Run

        /// <summary>
        /// Runs the selected methods over the selected scopes. Phases run one
        /// after another (discovery, then identification, then services), and
        /// methods within a phase run sequentially as well, because the modules
        /// share network resources and timeouts. Run concurrently, they would
        /// distort each other's response times.
        /// </summary>
        /// <param name="selectedScopes">Scopes (address ranges, hosts) to scan.</param>
        /// <param name="selectedMethodIds">Identifiers of the methods to run.</param>
        /// <param name="settings">Scan settings.</param>
        /// <param name="store">Device store that receives all observations.</param>
        /// <param name="cancellationToken">Cancels the run.</param>
        /// <returns>The result of the run.</returns>
        /// <exception cref="ArgumentNullException">An argument is null.</exception>
        /// <exception cref="InvalidOperationException">A run is already in progress.</exception>
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
                throw new InvalidOperationException("A scan is already running. Call Stop first.");
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

                        // Restricted here rather than once before the run: by
                        // the time this method's turn comes, the preceding
                        // methods have already found devices, and those are
                        // exactly the ones it should query.
                        List<ScanTargetEntry> forMethod = settings.IsRestrictedToKnown(method.Id)
                            ? KeepKnown(targets, store)
                            : targets;

                        ScanMethodOutcome outcome = await RunOneAsync(method, scopes, forMethod, settings, store, _cts.Token);
                        outcomes.Add(outcome);
                        MethodFinished?.Invoke(outcome);
                    }

                    if (_cts.IsCancellationRequested) break;
                }

                // Duplicate detection deliberately does *not* run here.
                //
                // It belongs at the end of the run; any finding made during the
                // run would be provisional, because the second device with the
                // same address may still turn up. It writes Device.Conflicts
                // and Device.ConflictDetails, however, and both are bound
                // properties. This run executes on the thread pool; written
                // from there, the UI crashes. The caller therefore calls
                // DuplicateDetector.Analyze itself once it is back on its own
                // thread and sets the count afterwards.
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
        /// Flushes the system ARP cache. A failure does not abort the run:
        /// without elevated privileges flushing is not possible, and the scan
        /// then returns the cached mappings.
        /// </summary>
        private static void FlushArpCache()
        {
            try { Services.PlatformServices.ArpOrNull?.FlushArpCache(); }
            catch (Exception) { /* see summary */ }
        }

        /// <summary>
        /// Reduces the targets to devices already known. A run over a whole /24
        /// then becomes a follow-up on the few addresses actually in use,
        /// which is the typical second and third pass.
        /// <para>
        /// Host names are always kept: whether they belong to a known device is
        /// only known after resolution.
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
                    // Modules report from arbitrary tasks. The store is not
                    // thread-safe, so reports are serialized here.
                    lock (_reportLock)
                    {
                        store.Observe(observation);
                    }
                },
                ReportStepProgress = (current, responded, total, detail, step, stepCount) =>
                    ProgressChanged?.Invoke(new ScanProgress
                    {
                        MethodId = method.Id,
                        MethodName = method.DisplayName,
                        Phase = method.Phase,
                        Current = current,
                        Responded = responded,
                        Total = total,
                        Detail = detail,
                        Step = step,
                        StepCount = stepCount
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
                    Reason = "cancelled",
                    Duration = DateTimeOffset.Now - started
                };
            }
            catch (Exception ex)
            {
                // A failed method must not end the run; the remaining methods
                // still deliver results.
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
