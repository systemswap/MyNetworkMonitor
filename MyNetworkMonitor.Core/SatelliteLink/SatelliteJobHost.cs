namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Der laufende Auftrag eines Satelliten - genau einer, ueber alle
    /// Empfaenger hinweg.
    /// <para>
    /// Gemeinsam und nicht je Verbindung, weil beides davon abhaengt: ein
    /// Satellit nimmt nur einen Auftrag zur Zeit an (sonst scannte er dasselbe
    /// Segment doppelt und kaeme sich mit den eigenen Paketen ins Gehege), und
    /// die Frage "darf der hier abbrechen" laesst sich nur beantworten, wenn
    /// man weiss, wer ihn gestartet hat.
    /// </para>
    /// <para>
    /// Siehe SATELLIT.md, Abschnitte 1 und 3.
    /// </para>
    /// </summary>
    public sealed class SatelliteJobHost
    {
        private readonly Lock _sync = new();

        private CancellationTokenSource? _cts;
        private string? _jobId;
        private string? _owner;

        /// <summary>
        /// Ob jeder freigegebene Empfaenger abbrechen darf, nicht nur der
        /// Auftraggeber.
        /// <para>
        /// Vorgabe an: ein haengender Auftrag sperrt den Satelliten fuer alle,
        /// und wer gerade davorsitzt, soll ihn freibekommen, ohne den
        /// Auftraggeber suchen zu muessen.
        /// </para>
        /// </summary>
        public bool AllowCancelFromAnyReceiver { get; set; } = true;

        /// <summary>Kennung des laufenden Auftrags, oder <c>null</c>.</summary>
        public string? CurrentJobId
        {
            get { lock (_sync) return _jobId; }
        }

        /// <summary>Wer ihn gestartet hat, oder <c>null</c>.</summary>
        public string? Owner
        {
            get { lock (_sync) return _owner; }
        }

        /// <summary>
        /// Nimmt einen Auftrag an, wenn keiner laeuft. Gibt die Abbruchquelle
        /// zurueck, oder <c>null</c>, wenn schon einer laeuft.
        /// </summary>
        public CancellationTokenSource? TryStart(string jobId, string owner, CancellationToken linked)
        {
            lock (_sync)
            {
                if (_jobId is not null) return null;

                _jobId = jobId;
                _owner = owner;
                _cts = CancellationTokenSource.CreateLinkedTokenSource(linked);

                return _cts;
            }
        }

        /// <summary>
        /// Bricht ab, wenn der Anfragende das darf.
        /// </summary>
        /// <param name="jobId">
        /// Die gemeinte Auftragskennung, oder <c>null</c> fuer "was auch immer
        /// gerade laeuft" - fuer den Fall, dass etwas haengt und niemand mehr
        /// weiss, wie der Auftrag hiess.
        /// </param>
        /// <param name="requester">Wer abbrechen will.</param>
        /// <param name="reason">Warum es nicht ging, falls es nicht ging.</param>
        public bool TryCancel(string? jobId, string requester, out string reason)
        {
            lock (_sync)
            {
                if (_jobId is null)
                {
                    reason = "No job is running.";
                    return false;
                }

                if (jobId is not null && jobId != _jobId)
                {
                    reason = $"Job {jobId} is not the one running ({_jobId}).";
                    return false;
                }

                bool isOwner = string.Equals(_owner, requester, StringComparison.OrdinalIgnoreCase);

                if (!isOwner && !AllowCancelFromAnyReceiver)
                {
                    reason = "Only the main scanner that started this job may cancel it.";
                    return false;
                }

                reason = string.Empty;

                try { _cts?.Cancel(); } catch { }
                return true;
            }
        }

        /// <summary>Meldet, dass der Auftrag durch ist - egal wie.</summary>
        public void Finish(string jobId)
        {
            lock (_sync)
            {
                if (_jobId != jobId) return;

                _jobId = null;
                _owner = null;

                try { _cts?.Dispose(); } catch { }
                _cts = null;
            }
        }
    }
}
