using MyNetworkMonitor;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public class ScanningMethod_NetBios
{
    //public event Action<IPToScan> NetbiosIPScanFinished;
    //public event Action<int, int, int> ProgressUpdated;
    //public event Action<bool> NetbiosScanFinished;

    //private int current = 0;
    //private int responded = 0;
    //private int total = 0;

    //public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan, CancellationToken cancellationToken)
    //{
    //    current = 0;
    //    responded = 0;
    //    total = IPsToScan.Count;

    //    var options = new ParallelOptions
    //    {
    //        MaxDegreeOfParallelism = 20, // Begrenze gleichzeitige NetBIOS-Anfragen auf 20
    //        CancellationToken = cancellationToken
    //    };

    //    List<Task> tasks = new List<Task>();

    //    await Task.Run(() => Parallel.ForEach(IPsToScan, options, ip =>
    //    {
    //        if (cancellationToken.IsCancellationRequested) return;

    //        int currentValue = Interlocked.Increment(ref current);
    //        ProgressUpdated?.Invoke(current, responded, total);

    //        ip.UsedScanMethod = ScanMethod.NetBios;

    //        // NetBIOS-Anfrage mit Timeout (5 Sekunden)
    //        var task = RunWithTimeout(QueryNetBiosAsync(ip, cancellationToken), TimeSpan.FromSeconds(5));
    //        lock (tasks) tasks.Add(task);
    //    }));

    //    // **Warte auf ALLE NetBIOS-Scans, bevor das Event ausgelöst wird**
    //    await Task.WhenAll(tasks);

    //    NetbiosScanFinished?.Invoke(true);
    //}

    //private async Task QueryNetBiosAsync(IPToScan iPToScan, CancellationToken cancellationToken)
    //{
    //    try
    //    {
    //        if (GetRemoteNetBiosName(IPAddress.Parse(iPToScan.IPorHostname), out string nbName, out string nbDomain, out string macAddress))
    //        {
    //            iPToScan.NetBiosHostname = nbName;

    //            if (!string.IsNullOrEmpty(nbName))
    //            {
    //                int respondedValue = Interlocked.Increment(ref responded);
    //                ProgressUpdated?.Invoke(current, responded, total);
    //                NetbiosIPScanFinished?.Invoke(iPToScan);
    //            }
    //        }
    //    }
    //    catch (Exception ex)
    //    {
    //        Console.WriteLine($"⚠ Fehler bei NetBIOS-Scan für {iPToScan.IPorHostname}: {ex.Message}");
    //    }
    //}

    //private static bool GetRemoteNetBiosName(IPAddress targetAddress, out string nbName, out string nbDomainOrWorkgroupName, out string macAddress, int receiveTimeOut = 5000, int retries = 1)
    //{
    //    byte[] nameRequest = new byte[]{
    //        0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    //        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
    //        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    //        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    //        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    //        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    //        0x00, 0x01 };

    //    do
    //    {
    //        byte[] receiveBuffer = new byte[1024];
    //        using Socket requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    //        requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, receiveTimeOut);

    //        nbName = null;
    //        nbDomainOrWorkgroupName = null;
    //        macAddress = "00-00-00-00-00-00";

    //        EndPoint remoteEndpoint = new IPEndPoint(targetAddress, 137);
    //        IPEndPoint originEndpoint = new IPEndPoint(IPAddress.Any, 0);
    //        requestSocket.Bind(originEndpoint);
    //        requestSocket.SendTo(nameRequest, remoteEndpoint);

    //        try
    //        {
    //            int receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
    //            if (receivedByteCount >= 90)
    //            {
    //                Encoding enc = new ASCIIEncoding();
    //                nbName = enc.GetString(receiveBuffer, 57, 15).Trim();
    //                nbDomainOrWorkgroupName = enc.GetString(receiveBuffer, 75, 15).Trim();

    //                int macOffset = receivedByteCount - 6;
    //                if (macOffset > 0 && receivedByteCount >= macOffset + 6)
    //                {
    //                    macAddress = BitConverter.ToString(receiveBuffer, macOffset, 6);
    //                }
    //                return true;
    //            }
    //        }
    //        catch (SocketException) { }

    //        retries--;
    //    } while (retries >= 0);

    //    return false;
    //}

    //private async Task RunWithTimeout(Task task, TimeSpan timeout)
    //{
    //    var timeoutTask = Task.Delay(timeout);
    //    var completedTask = await Task.WhenAny(task, timeoutTask);

    //    if (completedTask == timeoutTask)
    //    {
    //        Console.WriteLine("⚠ NetBIOS-Scan für eine IP abgebrochen (Timeout)");
    //    }
    //}




    public event Action<IPToScan> NetbiosIPScanFinished;
    public event Action<int, int, int> ProgressUpdated;
    public event Action<bool> NetbiosScanFinished;

    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private static readonly byte[] NameRequest = {
        0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01
    };

    //public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan, CancellationToken cancellationToken, int maxParallelScans = 20)
    //{
    //    current = 0;
    //    responded = 0;
    //    total = IPsToScan.Count;

    //    var options = new ParallelOptions
    //    {
    //        MaxDegreeOfParallelism = maxParallelScans,
    //        CancellationToken = cancellationToken
    //    };

    //    var tasks = new ConcurrentBag<Task>();

    //    Parallel.ForEach(IPsToScan, options, ip =>
    //    {
    //        if (cancellationToken.IsCancellationRequested) return;

    //        Interlocked.Increment(ref current);
    //        ProgressUpdated?.Invoke(current, responded, total);

    //        ip.UsedScanMethod = ScanMethod.NetBios;

    //        tasks.Add(RunWithTimeout(QueryNetBiosAsync(ip, cancellationToken), TimeSpan.FromSeconds(5)));
    //    });

    //    await Task.WhenAll(tasks);
    //    NetbiosScanFinished?.Invoke(true);
    //}



    public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan, CancellationToken cancellationToken, int maxParallelScans = 50)
    {
        current = 0;
        responded = 0;
        total = IPsToScan.Count;

        var semaphore = new SemaphoreSlim(maxParallelScans); // Begrenzung der gleichzeitigen Tasks
        var tasks = new List<Task>();

        foreach (var ip in IPsToScan)
        {
            if (cancellationToken.IsCancellationRequested) break;

            await semaphore.WaitAsync(cancellationToken); // Erlaubt nur `maxParallelScans` gleichzeitige Anfragen

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    Interlocked.Increment(ref current);
                    ProgressUpdated?.Invoke(current, responded, total);

                    ip.UsedScanMethod = ScanMethod.NetBios;
                    bool success = await RunWithTimeout(QueryNetBiosAsync(ip, cancellationToken), TimeSpan.FromSeconds(5));

                    if (success)
                    {
                        //Interlocked.Increment(ref responded);
                        //ProgressUpdated?.Invoke(current, responded, total);
                        //NetbiosIPScanFinished?.Invoke(ip);
                    }
                }
                finally
                {
                    semaphore.Release(); // Gibt den Slot nach Abschluss frei
                }
            }));
        }

        await Task.WhenAll(tasks); // Warte auf ALLE Scans

        NetbiosScanFinished?.Invoke(true);
    }


    private async Task QueryNetBiosAsync(IPToScan iPToScan, CancellationToken cancellationToken)
    {
        try
        {
            if (GetRemoteNetBiosName(IPAddress.Parse(iPToScan.IPorHostname), out string nbName, out _, out _))
            {
                iPToScan.NetBiosHostname = nbName;

                if (!string.IsNullOrEmpty(nbName))
                {
                    Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, responded, total);
                    NetbiosIPScanFinished?.Invoke(iPToScan);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠ Fehler bei NetBIOS-Scan für {iPToScan.IPorHostname}: {ex.Message}");
        }
    }

    private static bool GetRemoteNetBiosName(IPAddress targetAddress, out string nbName, out string nbDomainOrWorkgroupName, out string macAddress, int receiveTimeOut = 5000, int retries = 1)
    {
        nbName = null;
        nbDomainOrWorkgroupName = null;
        macAddress = "00-00-00-00-00-00";

        byte[] receiveBuffer = new byte[1024];

        do
        {
            using Socket requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, receiveTimeOut);

            EndPoint remoteEndpoint = new IPEndPoint(targetAddress, 137);
            requestSocket.SendTo(NameRequest, remoteEndpoint);

            try
            {
                int receivedByteCount = requestSocket.Receive(receiveBuffer);
                if (receivedByteCount >= 90)
                {
                    Encoding enc = new ASCIIEncoding();
                    nbName = enc.GetString(receiveBuffer, 57, 15).Trim();
                    nbDomainOrWorkgroupName = enc.GetString(receiveBuffer, 75, 15).Trim();

                    int macOffset = receivedByteCount - 6;
                    if (macOffset > 0 && receivedByteCount >= macOffset + 6)
                    {
                        macAddress = BitConverter.ToString(receiveBuffer, macOffset, 6);
                    }
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

