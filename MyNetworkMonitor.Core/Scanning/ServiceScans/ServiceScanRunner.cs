using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>Ein Befund: was an einem Ziel fuer einen Dienst herauskam.</summary>
    /// <param name="Address">Das gepruefte Ziel.</param>
    /// <param name="Result">Die Portergebnisse dieses einen Dienstes.</param>
    public sealed record ServiceFinding(string Address, ServiceResult Result);

    /// <summary>Der Stand eines Laufs, wie ihn die Anzeige braucht.</summary>
    /// <param name="Current">Abgeschickte Pruefungen (Dienst mal Ziel).</param>
    /// <param name="Responded">Davon die, an denen etwas offen war.</param>
    /// <param name="Total">Alle Pruefungen des Laufs.</param>
    /// <param name="Service">Der Dienst, der gerade an der Reihe ist.</param>
    /// <param name="Step">Der wievielte Dienst.</param>
    /// <param name="StepCount">Von wie vielen.</param>
    public sealed record ServiceScanProgress(
        int Current, int Responded, int Total, string Service, int Step, int StepCount);

    /// <summary>
    /// Fuehrt die Diensterkennung aus: <b>ein Dienst nach dem anderen</b>, und
    /// innerhalb eines Dienstes alle Ziele nebenlaeufig.
    /// <para>
    /// Vorher war es andersherum - 30 Ziele gleichzeitig, jedes fuer sich
    /// durch alle Dienste. Zaehlen liessen sich damit nur Ziele: welcher
    /// Dienst gerade laeuft, gab es im Ablauf gar nicht, weil zu jedem
    /// Zeitpunkt 30 verschiedene liefen. Herum gedreht ist die Frage
    /// beantwortbar - "SSH, der 11. von 24" -, und ein langsamer Dienst
    /// versteckt sich nicht mehr hinter den schnellen.
    /// </para>
    /// <para>
    /// Die Drosseln sind dieselben wie vorher: 30 Ziele nebeneinander, je
    /// Ziel bis zu 50 Ports. Der Umbau soll den Fortschritt ehrlich machen,
    /// nicht die Last im Netz verschieben.
    /// </para>
    /// </summary>
    public sealed class ServiceScanRunner
    {
        /// <summary>Ziele nebeneinander - vorher <c>MaxParallelIPs</c>.</summary>
        private const int MaxParallelTargets = 30;

        /// <summary>Ports je Ziel nebeneinander.</summary>
        private const int MaxParallelPorts = 50;

        private int _current;
        private int _responded;

        public ProbeContext Context { get; init; } = new();

        /// <summary>Ein Ziel ist fuer einen Dienst fertig geprueft.</summary>
        public event Action<ServiceFinding>? Found;

        public event Action<ServiceScanProgress>? ProgressUpdated;

        /// <summary>
        /// Prueft die gewaehlten Dienste an den gewaehlten Zielen.
        /// </summary>
        /// <param name="portsByService">
        /// Die Ports je Dienst aus der Dienstverwaltung. Fehlt ein Dienst
        /// darin, gelten die Vorgaben seiner Sonde; steht dort eine
        /// <em>leere</em> Liste, wird er nicht geprueft - das ist dann eine
        /// Entscheidung des Nutzers und kein fehlender Eintrag.
        /// </param>
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
                    // Nichts zu pruefen, die Ziele gelten trotzdem als
                    // abgearbeitet - sonst bliebe der Balken stehen.
                    Interlocked.Add(ref _current, targets.Count);
                    Report(probe, step, probes.Count, total);
                    continue;
                }

                try
                {
                    await probe.PrepareAsync(Context, targets, token);
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // Misslingt die Vorbereitung eines Dienstes, wird eben
                    // dieser Dienst nichts finden - die uebrigen 23 gehen das
                    // nichts an.
                }

                await RunProbeAsync(probe, targets, ports, step, probes.Count, total, token);
            }
        }

        /// <summary>Ein Dienst ueber alle Ziele.</summary>
        private async Task RunProbeAsync(
            IServiceProbe probe, IReadOnlyList<string> targets, List<int> ports,
            int step, int stepCount, int total, CancellationToken token)
        {
            using SemaphoreSlim targetSlots = new(MaxParallelTargets);

            IEnumerable<Task> runs = targets.Select(async address =>
            {
                await targetSlots.WaitAsync(token);

                // Gezaehlt wird die abgeschickte Pruefung, nicht die fertige -
                // dieselbe Regel wie in den uebrigen Verfahren. Stiegen beide
                // Zahlen im selben Augenblick, saehe man nie, dass Ziele
                // unterwegs sind; an der Diensterkennung haengt jedes Ziel
                // lange in Zeitueberschreitungen, und genau diese Wartezeit
                // soll am Abstand der beiden Zahlen ablesbar sein.
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
                    // Abbruch ist kein Fehlschlag dieses Ziels.
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // Ein einzelnes Ziel darf den Lauf nicht beenden.
                    //
                    // Der Ablauf geht Dienst fuer Dienst: eine Ausnahme, die
                    // bis hierher steigt, riss frueher die ganze Schleife mit,
                    // und jeder Dienst, der noch an der Reihe gewesen waere,
                    // wurde nie geprueft. Genau so ist ein Lauf nach dem
                    // zehnten von 24 Diensten geendet - eine Gegenstelle hatte
                    // die Verbindung zugeschlagen (IOException). Gemeldet wurde
                    // er trotzdem als beendet, und es sah aus, als kenne die
                    // Erkennung die Haelfte der Dienste nicht mehr.
                }
                finally
                {
                    Report(probe, step, stepCount, total);
                    targetSlots.Release();
                }
            });

            await Task.WhenAll(runs);
        }

        /// <summary>Ein Dienst an einem Ziel, ueber alle seine Ports.</summary>
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
                    PortResult portResult = await probe.ProbeAsync(Context, address, port, token);

                    lock (result.Ports) result.Ports.Add(portResult);
                }
                catch (OperationCanceledException)
                {
                    // siehe oben
                }
                catch (Exception) when (!token.IsCancellationRequested)
                {
                    // Und ein einzelner Port darf weder das Ziel noch den Lauf
                    // beenden - siehe die Anmerkung eine Ebene hoeher.
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
        /// Die Ports dieses Dienstes. Ohne Eintrag in der Verwaltung gelten
        /// die Vorgaben der Sonde - siehe Anmerkung an <see cref="RunAsync"/>.
        /// </summary>
        private static List<int> PortsFor(
            IServiceProbe probe, IReadOnlyDictionary<ServiceType, List<int>> portsByService) =>
            portsByService.TryGetValue(probe.Service, out List<int>? ports) && ports is not null
                ? ports
                : [.. probe.DefaultPorts];

        /// <summary>
        /// Massstab wie in der Tabelle: offen oder erkannter Dienst ist ein
        /// Fund, alles Uebrige - zu, gefiltert, keine Antwort - nicht.
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
