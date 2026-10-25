// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>A finding: the result of one service on one target.</summary>
    /// <param name="Address">The checked target.</param>
    /// <param name="Result">The port results of this one service.</param>
    public sealed record ServiceFinding(string Address, ServiceResult Result);

    /// <summary>The progress of a run, as the display needs it.</summary>
    /// <param name="Current">Checks started (services times targets).</param>
    /// <param name="Responded">Of these, the checks that found something open.</param>
    /// <param name="Total">All checks of the run.</param>
    /// <param name="Service">The service currently being checked.</param>
    /// <param name="Step">The position of this service in the run, starting at 1.</param>
    /// <param name="StepCount">The number of services in the run.</param>
    public sealed record ServiceScanProgress(
        int Current, int Responded, int Total, string Service, int Step, int StepCount);

    /// <summary>
    /// Runs service detection: <b>one service after the other</b>, and within
    /// a service all targets concurrently.
    /// <para>
    /// This order makes the progress answerable ("SSH, 11 of 24"), and a slow
    /// service does not hide behind the fast ones. Running each target
    /// through all services instead would leave no single "current service"
    /// to report.
    /// </para>
    /// <para>
    /// Throttling: 30 targets in parallel, up to 50 ports per target.
    /// </para>
    /// </summary>
    public sealed class ServiceScanRunner
    {
        /// <summary>Targets checked in parallel.</summary>
        private const int MaxParallelTargets = 30;

        /// <summary>Ports per target checked in parallel.</summary>
        private const int MaxParallelPorts = 50;

        private int _current;
        private int _responded;

        /// <summary>The conditions for all probes of the run.</summary>
        public ProbeContext Context { get; init; } = new();

        /// <summary>
        /// The services that may be actively queried, enabled in the service
        /// manager; empty by default.
        /// <para>
        /// Per service and not for the whole run, because the request changes
        /// anything only for a few protocols. What it means for SECS/GEM is
        /// described at <see cref="ProbeContext.ActiveInquiry"/>.
        /// </para>
        /// </summary>
        public IReadOnlySet<ServiceType> ActiveInquiryServices { get; init; } =
            new HashSet<ServiceType>();

        /// <summary>The context for one probe, with its own permission for active inquiry.</summary>
        private ProbeContext ContextFor(IServiceProbe probe) =>
            ActiveInquiryServices.Contains(probe.Service)
                ? new ProbeContext
                {
                    TimeoutMs = Context.TimeoutMs,
                    RetryCount = Context.RetryCount,
                    ActiveInquiry = true
                }
                : Context;

        /// <summary>Raised when one target has been checked for one service.</summary>
        public event Action<ServiceFinding>? Found;

        /// <summary>Raised whenever the progress of the run changes.</summary>
        public event Action<ServiceScanProgress>? ProgressUpdated;

        /// <summary>
        /// Checks the selected services on the selected targets.
        /// </summary>
        /// <param name="targets">The addresses to check.</param>
        /// <param name="services">The services to check; services without a probe are skipped.</param>
        /// <param name="portsByService">
        /// The ports per service from the service manager. If a service is
        /// missing, the defaults of its probe apply; an <em>empty</em> list
        /// means the service is not checked, which is a deliberate setting
        /// and not a missing entry.
        /// </param>
        /// <param name="token">Cancels the run.</param>
        /// <exception cref="ArgumentNullException">An argument is <c>null</c>.</exception>
        /// <exception cref="OperationCanceledException">The run was cancelled.</exception>
        public async Task RunAsync(
            IReadOnlyList<string> targets,
            IReadOnlyList<ServiceType> services,
            IReadOnlyDictionary<ServiceType, List<int>> portsByService,
            CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(targets);
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(portsByService);

            IReadOnlyList<IServiceProbe> probes = ServiceProbes.InScanOrder(services);
            if (probes.Count == 0 || targets.Count == 0) return;

            _current = 0;
            _responded = 0;

            int total = probes.Count * targets.Count;
            int step = 0;

            foreach (IServiceProbe probe in probes)
            {
                token.ThrowIfCancellationRequested();

                step++;
                Report(probe, step, probes.Count, total);

                List<int> ports = PortsFor(probe, portsByService);
                if (ports.Count == 0)
                {
                    // Nothing to check; the targets still count as done,
                    // otherwise the progress bar would stall.
                    Interlocked.Add(ref _current, targets.Count);
                    Report(probe, step, probes.Count, total);
                    continue;
                }

                try
                {
                    await probe.PrepareAsync(ContextFor(probe), targets, token);
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // If the preparation of a service fails, that service
                    // finds nothing; the other services are not affected.
                }

                await RunProbeAsync(probe, targets, ports, step, probes.Count, total, token);
            }
        }

        /// <summary>Runs one service over all targets.</summary>
        private async Task RunProbeAsync(
            IServiceProbe probe, IReadOnlyList<string> targets, List<int> ports,
            int step, int stepCount, int total, CancellationToken token)
        {
            using SemaphoreSlim targetSlots = new(MaxParallelTargets);

            IEnumerable<Task> runs = targets.Select(async address =>
            {
                await targetSlots.WaitAsync(token);

                // The started check is counted, not the finished one; the same
                // rule as in the other scan methods. If both numbers rose at
                // the same moment, targets in progress would never be visible;
                // in service detection every target spends a long time in
                // timeouts, and that waiting time should show as the gap
                // between the two numbers.
                Interlocked.Increment(ref _current);
                Report(probe, step, stepCount, total);

                try
                {
                    ServiceResult result = await ProbeTargetAsync(probe, address, ports, token);

                    if (HasOpenPort(result)) Interlocked.Increment(ref _responded);

                    Found?.Invoke(new ServiceFinding(address, result));
                }
                catch (OperationCanceledException)
                {
                    // Cancellation is not a failure of this target.
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // A single target must not end the run.
                    //
                    // The run goes service by service: an exception rising to
                    // this point would abort the whole loop, and every service
                    // still to come would never be checked. A remote side that
                    // closes the connection (IOException) is enough for that;
                    // the run is still reported as finished, and it looks as if
                    // detection no longer knew half of the services.
                }
                finally
                {
                    Report(probe, step, stepCount, total);
                    targetSlots.Release();
                }
            });

            await Task.WhenAll(runs);
        }

        /// <summary>Checks one service on one target, over all its ports.</summary>
        private async Task<ServiceResult> ProbeTargetAsync(
            IServiceProbe probe, string address, List<int> ports, CancellationToken token)
        {
            ServiceResult result = new() { Service = probe.Service };

            using SemaphoreSlim portSlots = new(MaxParallelPorts);

            IEnumerable<Task> checks = ports.Distinct().Select(async port =>
            {
                await portSlots.WaitAsync(token);

                try
                {
                    PortResult portResult = await probe.ProbeAsync(ContextFor(probe), address, port, token);

                    lock (result.Ports) result.Ports.Add(portResult);
                }
                catch (OperationCanceledException)
                {
                    // see above
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // A single port must end neither the target nor the run;
                    // see the note one level up.
                }
                finally
                {
                    portSlots.Release();
                }
            });

            await Task.WhenAll(checks);

            return result;
        }

        /// <summary>
        /// The ports of this service. Without an entry in the service manager,
        /// the defaults of the probe apply; see the note at <see cref="RunAsync"/>.
        /// </summary>
        private static List<int> PortsFor(
            IServiceProbe probe, IReadOnlyDictionary<ServiceType, List<int>> portsByService) =>
            portsByService.TryGetValue(probe.Service, out List<int>? ports) && ports is not null
                ? ports
                : [.. probe.DefaultPorts];

        /// <summary>
        /// Same criterion as in the table: open or a detected service is a
        /// finding; everything else (closed, filtered, no response) is not.
        /// </summary>
        private static bool HasOpenPort(ServiceResult result)
        {
            lock (result.Ports)
            {
                return result.Ports.Any(p => p.Status is PortStatus.Open or PortStatus.IsRunning);
            }
        }

        private void Report(IServiceProbe probe, int step, int stepCount, int total) =>
            ProgressUpdated?.Invoke(new ServiceScanProgress(
                Volatile.Read(ref _current),
                Volatile.Read(ref _responded),
                total,
                probe.Service.ToString(),
                step,
                stepCount));
    }
}
