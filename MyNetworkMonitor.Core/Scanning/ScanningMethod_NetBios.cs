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

public class ScanningMethod_NetBios
{
    public event Action<IPToScan> NetbiosIPScanFinished;
    public event Action<int, int, int, ScanStatus> ProgressUpdated;
    public event Action<bool> NetbiosScanFinished;
    

    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel(); // 🔹 Scan abbrechen
            // Hier NICHT aufraeumen und ersetzen: die Schleifen lesen _cts ueber
            // das Feld. Ein frisches CTS an dieser Stelle meldet ihnen wieder
            // "nicht abgebrochen", und der Lauf geht weiter, statt zu enden.
            // Das Zuruecksetzen erledigt StartNewScan beim naechsten Lauf.
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

        // 🔹 Zähler zurücksetzen
        current = 0;
        responded = 0;
        total = 0;
    }



    public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan, int maxParallelScans = 50)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;

        var semaphore = new SemaphoreSlim(maxParallelScans); // Begrenzung der gleichzeitigen Tasks
        var tasks = new List<Task>();

        foreach (var ip in IPsToScan)
        {
            if (_cts.Token.IsCancellationRequested) break;  // 🔹 Saubere Abbruchprüfung

            await semaphore.WaitAsync(_cts.Token); // Erlaubt nur `maxParallelScans` gleichzeitige Anfragen

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (_cts.Token.IsCancellationRequested) return;  // 🔹 Vor dem Start abbrechen                    

                    ip.UsedScanMethod = ScanMethod.NetBios;
                    await RunWithTimeout(QueryNetBiosAsync(ip, _cts.Token), TimeSpan.FromSeconds(5));
                }
                finally
                {
                    semaphore.Release(); // Gibt den Slot nach Abschluss frei
                }
            }));
        }

        await Task.WhenAll(tasks.Where(t => t != null)); // Warte auf ALLE Scans

        NetbiosScanFinished?.Invoke(true);
    }


    private async Task QueryNetBiosAsync(IPToScan iPToScan, CancellationToken cancellationToken)
    {
        try
        {
            if (cancellationToken.IsCancellationRequested) return; // 🔹 Abbruchprüfung

            // Die abgeschickte Anfrage zaehlt, nicht die fertige. Die Anzeige
            // stellt gesendet, geantwortet und gesamt nebeneinander - daran ist
            // abzulesen, dass noch gewartet wird.
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            if (GetRemoteNetBiosName(IPAddress.Parse(iPToScan.IPorHostname), out string? nbName, out string? nbWorkgroup, out _))
            {
                if (cancellationToken.IsCancellationRequested) return; // 🔹 Abbruchprüfung

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
    /// workgroup from it; see <see cref="NetBiosNodeStatus"/>.
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

