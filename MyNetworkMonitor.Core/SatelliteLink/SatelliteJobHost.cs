// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// The running job of a satellite: exactly one, across all main scanners.
    /// <para>
    /// Shared rather than per connection because two things depend on it: a
    /// satellite accepts only one job at a time (otherwise it would scan the
    /// same segment twice and its own packets would interfere), and the
    /// question "may this one cancel" can only be answered when it is known who
    /// started the job.
    /// </para>
    /// <para>
    /// See SATELLIT.md, sections 1 and 3.
    /// </para>
    /// </summary>
    public sealed class SatelliteJobHost
    {
        private readonly Lock _sync = new();

        private CancellationTokenSource? _cts;
        private string? _jobId;
        private string? _owner;

        /// <summary>
        /// Whether every approved main scanner may cancel, not only the one
        /// that started the job.
        /// <para>
        /// On by default: a hanging job blocks the satellite for everyone, and
        /// whoever is at a main scanner should be able to release it without
        /// tracking down the one that started it.
        /// </para>
        /// </summary>
        public bool AllowCancelFromAnyReceiver { get; set; } = true;

        /// <summary>Identifier of the running job, or <c>null</c>.</summary>
        public string? CurrentJobId
        {
            get { lock (_sync) return _jobId; }
        }

        /// <summary>The main scanner that started it, or <c>null</c>.</summary>
        public string? Owner
        {
            get { lock (_sync) return _owner; }
        }

        /// <summary>
        /// Accepts a job if none is running.
        /// </summary>
        /// <param name="jobId">Identifier of the new job.</param>
        /// <param name="owner">The main scanner that starts it.</param>
        /// <param name="linked">Token the job's cancellation source is linked to.</param>
        /// <returns>The cancellation source of the job, or <c>null</c> if a job is already running.</returns>
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
        /// Cancels if the requester is allowed to.
        /// </summary>
        /// <param name="jobId">
        /// The intended job identifier, or <c>null</c> for "whatever is running
        /// right now", for the case that something hangs and the job identifier
        /// is no longer known.
        /// </param>
        /// <param name="requester">The main scanner that wants to cancel.</param>
        /// <param name="reason">Why cancelling was refused; empty on success.</param>
        /// <returns>True if cancellation was requested.</returns>
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

        /// <summary>
        /// Cancels whatever is running, regardless of who started it.
        /// <para>
        /// For the stop button on the satellite itself. Local operation may
        /// always stop it; <see cref="AllowCancelFromAnyReceiver"/> only governs
        /// who may do so remotely.
        /// </para>
        /// </summary>
        /// <returns>True if a job was running.</returns>
        public bool CancelCurrent()
        {
            lock (_sync)
            {
                if (_jobId is null) return false;

                try { _cts?.Cancel(); } catch { }
                return true;
            }
        }

        /// <summary>Reports that the job has ended, however it ended.</summary>
        /// <param name="jobId">The job that ended; other identifiers are ignored.</param>
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
