using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Bindet das bestehende <see cref="ScanningMethods_Ping"/> in die Engine
    /// ein. Vorlage fuer die uebrigen 15 Module: das Modul selbst bleibt
    /// unveraendert, der Adapter setzt nur seine Ereignisse auf
    /// <see cref="ScanContext.Report"/> um und leitet den Abbruch weiter.
    /// <para>
    /// <b>Bewusst nur IPv4.</b> <c>ScanningMethods_Ping.PingTask</c> prueft
    /// jedes Ziel mit <c>SupportMethods.Is_Valid_IP</c>, und das ist eine reine
    /// IPv4-Regex - IPv6-Ziele werden dort ohne Meldung verworfen. Der Adapter
    /// gibt darum <see cref="FamilySupport.IPv4"/> an, statt eine Faehigkeit zu
    /// behaupten, die das Modul nicht hat. Das ICMPv6-Gegenstueck kommt als
    /// eigenes Verfahren (Echo an ff02::1), das ohnehin anders arbeitet: ein
    /// Paket an alle statt eines je Adresse.
    /// </para>
    /// </summary>
    public sealed class PingScanMethod : IScanMethod
    {
        public string Id => "ping";
        public string DisplayName => "Ping";
        public ScanPhase Phase => ScanPhase.Discovery;
        public FamilySupport Families => FamilySupport.IPv4;
        public bool IsPassive => false;
        public bool RequiresElevation => false;

        public ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (!context.HasTargetsOf(IpFamily.IPv4))
            {
                return ScanMethodAvailability.NotApplicable(
                    "Keine IPv4-Ziele ausgewaehlt. Fuer IPv6 arbeitet stattdessen der Multicast-Ping an ff02::1.");
            }

            return ScanMethodAvailability.Available;
        }

        public async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            List<ScanTargetEntry> targets = context.TargetsOf(IpFamily.IPv4).ToList();
            if (targets.Count == 0) return;

            // Das Modell der Engine auf das Modell des Moduls abbilden. Die
            // Zuordnung wird behalten, damit die Rueckmeldung des Moduls dem
            // richtigen Bereich zugeschlagen werden kann.
            Dictionary<string, ScanTargetEntry> byText = [];
            List<IPToScan> legacy = [];

            foreach (ScanTargetEntry target in targets)
            {
                string text = target.TargetText;
                if (string.IsNullOrEmpty(text) || !byText.TryAdd(text, target)) continue;

                legacy.Add(new IPToScan
                {
                    IPorHostname = text,
                    TimeOut = context.Settings.PortTimeoutMs,
                    IPGroupDescription = target.Scope.Scope.GroupDescription
                });
            }

            ScanningMethods_Ping ping = new();

            void OnProgress(int current, int responded, int total, ScanStatus status) =>
                context.ReportProgress(current, responded, total);

            void OnFinished(object? sender, ScanTask_Finished_EventArgs e)
            {
                IPToScan result = e.ipToScan;
                if (!IpAddressAnalyzer.TryAnalyze(result.IPorHostname, out IpAddressInfo? info) || info is null) return;

                byText.TryGetValue(result.IPorHostname, out ScanTargetEntry? origin);

                Dictionary<string, string>? details = null;
                if (!string.IsNullOrWhiteSpace(result.ResponseTime))
                {
                    details = new Dictionary<string, string> { ["Antwortzeit"] = $"{result.ResponseTime} ms" };
                }

                context.Report(new DeviceObservation
                {
                    Source = DisplayName,
                    Address = info,
                    IsResponding = result.PingStatus,
                    GroupDescription = origin?.Scope.Scope.GroupDescription,
                    Domain = string.IsNullOrWhiteSpace(origin?.Scope.Scope.Domain) ? null : origin!.Scope.Scope.Domain,
                    Details = details
                });
            }

            ping.ProgressUpdated += OnProgress;
            ping.Ping_Task_Finished += OnFinished;

            // Das Modul verwaltet seinen Abbruch selbst und kennt nur
            // StopScan(). Die Registrierung bruecktdas auf den Token der Engine.
            using CancellationTokenRegistration registration = cancellationToken.Register(ping.StopScan);

            try
            {
                await ping.PingIPsAsync(legacy);
            }
            finally
            {
                ping.ProgressUpdated -= OnProgress;
                ping.Ping_Task_Finished -= OnFinished;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
