// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor;
using MyNetworkMonitor.Core.Network;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Queries the NetBIOS name service of the targets (node status, RFC 1002) for host name and
/// workgroup.
/// </summary>
public class ScanningMethod_NetBios
{
    /// <summary>Raised for every target that answered with a host name.</summary>
    public event Action<IPToScan> NetbiosIPScanFinished;

    /// <summary>Reports progress as (sent, responded, total, status).</summary>
    public event Action<int, int, int, ScanStatus> ProgressUpdated;

    /// <summary>Raised when all queries of a run have finished.</summary>
    public event Action<bool> NetbiosScanFinished;
    

    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.

    /// <summary>
    /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
    /// </summary>
    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel();
            // Do NOT dispose and replace the source here: the loops read _cts through the
            // field. A fresh source at this point would report "not cancelled" to them and
            // the run would continue instead of ending. StartNewScan resets it for the next run.
        }

        ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped);
    }

    private void StartNewScan()
    {
        if (_cts != null)
        {
            if (!_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            _cts.Dispose();
        }
        _cts = new CancellationTokenSource();

        // Reset the counters.
        current = 0;
        responded = 0;
        total = 0;
    }



    /// <summary>
    /// Queries every target for its NetBIOS name table, with a time limit of five seconds per target.
    /// </summary>
    /// <param name="IPsToScan">The targets; each entry must be an IPv4 address.</param>
    /// <param name="maxParallelScans">Maximum number of concurrent queries.</param>
    public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan, int maxParallelScans = 50)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;

        var semaphore = new SemaphoreSlim(maxParallelScans); // Limits the concurrent queries.
        var tasks = new List<Task>();

        foreach (var ip in IPsToScan)
        {
            if (_cts.Token.IsCancellationRequested) break;

            await semaphore.WaitAsync(_cts.Token); // At most maxParallelScans queries at a time.

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (_cts.Token.IsCancellationRequested) return;

                    ip.UsedScanMethod = ScanMethod.NetBios;
                    await RunWithTimeout(QueryNetBiosAsync(ip, _cts.Token), TimeSpan.FromSeconds(5));
                }
                finally
                {
                    semaphore.Release();
                }
            }));
        }

        await Task.WhenAll(tasks.Where(t => t != null)); // Wait for all queries.

        NetbiosScanFinished?.Invoke(true);
    }


    private async Task QueryNetBiosAsync(IPToScan iPToScan, CancellationToken cancellationToken)
    {
        try
        {
            if (cancellationToken.IsCancellationRequested) return;

            // Count the sent query, not the finished one. The display shows sent, responded and
            // total side by side, which shows that answers are still pending.
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            if (GetRemoteNetBiosName(IPAddress.Parse(iPToScan.IPorHostname), out string? nbName, out string? nbWorkgroup, out _))
            {
                if (cancellationToken.IsCancellationRequested) return;

                iPToScan.NetBiosHostname = nbName ?? string.Empty;
                iPToScan.NetBiosWorkgroup = nbWorkgroup ?? string.Empty;

                if (!string.IsNullOrEmpty(nbName))
                {
                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    NetbiosIPScanFinished?.Invoke(iPToScan);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠ Fehler bei NetBIOS-Scan für {iPToScan.IPorHostname}: {ex.Message}");
        }
    }

    /// <summary>
    /// Asks a host for its NetBIOS name table (node status, RFC 1002, sections 4.2.17 and 4.2.18) and takes host name and
    /// workgroup from it; see <see cref="NetBiosNodeStatus"/>. The response is validated field by field against the
    /// transaction ID instead of being read at fixed offsets (see docs/FEHLERGEDAECHTNIS.md, No. 15).
    /// </summary>
    /// <param name="targetAddress">The IPv4 address of the host.</param>
    /// <param name="nbName">The host name, or null if the response contains none.</param>
    /// <param name="nbDomainOrWorkgroupName">The workgroup or domain, or null.</param>
    /// <param name="macAddress">The unit ID from the response (usually the MAC address), or "00-00-00-00-00-00".</param>
    /// <param name="receiveTimeOut">Waiting time for an answer per attempt in milliseconds.</param>
    /// <param name="retries">Further attempts after the first one.</param>
    /// <returns>True if the host answered with a node status response.</returns>
    private bool GetRemoteNetBiosName(IPAddress targetAddress, out string? nbName, out string? nbDomainOrWorkgroupName, out string macAddress, int receiveTimeOut = 5000, int retries = 1)
    {
        nbName = null;
        nbDomainOrWorkgroupName = null;
        macAddress = "00-00-00-00-00-00";

        byte[] receiveBuffer = new byte[1024];

        do
        {
            if (_cts.Token.IsCancellationRequested) return false;

            using Socket requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, receiveTimeOut);

            // Connect() instead of SendTo() on an unconnected socket: otherwise Receive() returns the answer of whichever
            // sender replies to the same local port first, not necessarily the queried host.
            requestSocket.Connect(new IPEndPoint(targetAddress, NetBiosNodeStatus.Port));
            ushort transactionId = (ushort)Random.Shared.Next(1, 0x10000);
            requestSocket.Send(NetBiosNodeStatus.BuildRequest(transactionId));

            if (_cts.Token.IsCancellationRequested) return false;

            try
            {
                int receivedByteCount = requestSocket.Receive(receiveBuffer);
                if (NetBiosNodeStatus.Parse(receiveBuffer.AsSpan(0, receivedByteCount), transactionId) is { } status)
                {
                    nbName = status.HostName;
                    nbDomainOrWorkgroupName = status.Workgroup;
                    if (status.UnitId.Length > 0) macAddress = status.UnitId;
                    return true;
                }
            }
            catch (SocketException) { }

            retries--;
        } while (retries >= 0);

        return false;
    }

    private async Task<bool> RunWithTimeout(Task task, TimeSpan timeout)
    {
        var timeoutTask = Task.Delay(timeout);
        var completedTask = await Task.WhenAny(task, timeoutTask);

        return completedTask != timeoutTask;
    }
}

