
using System.Collections.Generic;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using MyNetworkMonitor;
using System.Net;
using System.Collections.Concurrent;

public class ScanningMethod_SMBVersionCheck
{
    public event Action<int, int, int, ScanStatus> ProgressUpdated;
    public event Action<IPToScan> SMBIPScanFinished;    
    public event Action SMBScanFinished;


    public ScanningMethod_SMBVersionCheck()
    {

    }


    private async Task RunWithTimeout(Func<Task> action, TimeSpan timeout)
    {
        var task = action();
        if (await Task.WhenAny(task, Task.Delay(timeout, _cts.Token)) == task)
        {
            await task; // ✅ Die Task wurde erfolgreich beendet
        }
        else
        {
            Console.WriteLine($"❌ Timeout: SMB-Scan hat zu lange gedauert.");
        }
    }


    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

    //int currentValue = Interlocked.Increment(ref current);
    //Task.Run(() => ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running));

    //int respondedValue = Interlocked.Increment(ref responded);
    //Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running));

    //Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished));

    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel(); // 🔹 Scan abbrechen
            _cts.Dispose();
            _cts = new CancellationTokenSource();
        }

        Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped)); // 🔹 UI auf 0 setzen
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



    public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;
        int port = 445; // SMB-Standardport

        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = 20, // Begrenze gleichzeitige SMB-Anfragen auf 20
            CancellationToken = _cts.Token
        };

        // Verwende `ConcurrentBag<Task>`, um parallele Tasks sicher zu speichern
        //ConcurrentBag<Task> tasks = new ConcurrentBag<Task>();

        //await Task.Run(() => Parallel.ForEach(IPsToScan, options, ipToScan =>
        //{
        //    if (_cts.Token.IsCancellationRequested) return;

        //    ipToScan.UsedScanMethod = ScanMethod.SMB;

        //    // **SMB-Protokollversion prüfen (mit Timeout-Schutz)**
        //    var task = RunWithTimeout(() => CheckProtocolsAsync(ipToScan, port), TimeSpan.FromSeconds(10));
        //    tasks.Add(task);
        //}), _cts.Token);


        int maxDegreeOfParallelism = 50;
        using var semaphore = new SemaphoreSlim(maxDegreeOfParallelism);
        var tasks = new List<Task>();

        foreach (var ipToScan in IPsToScan)
        {
            if (_cts.Token.IsCancellationRequested) break;

            await semaphore.WaitAsync(_cts.Token); // Warte, bis ein Slot frei wird
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (_cts.Token.IsCancellationRequested) return;

                    ipToScan.UsedScanMethod = ScanMethod.SMB;

                    // SMB-Protokollversion prüfen mit Timeout-Schutz
                    await RunWithTimeout(() => CheckProtocolsAsync(ipToScan, port), TimeSpan.FromSeconds(10));
                }
                finally
                {
                    semaphore.Release(); // Slot freigeben
                }
            }, _cts.Token));
        }






        // **Warte auf ALLE SMB-Scans, bevor das Event ausgelöst wird**
        await Task.WhenAll(tasks.Where(t => t != null));

        // ✅ Garantiert: SMBScanFinished wird NUR ausgelöst, wenn alle SMB-Scans beendet sind
        //Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished));
        Task.Run(() => SMBScanFinished?.Invoke());
    }




    private async Task CheckProtocolsAsync(IPToScan ipToScan, int port)
    {
        int currentValue = Interlocked.Increment(ref current);
        Task.Run(() => ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running),_cts.Token);

        foreach (SMBDialects dialect in Enum.GetValues(typeof(SMBDialects)))
        {
            if (_cts.Token.IsCancellationRequested) return;           

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

                    var connectTask = socket.ConnectAsync(IPAddress.Parse(ipToScan.IPorHostname), port);
                    if (await Task.WhenAny(connectTask, Task.Delay(5000, _cts.Token)) != connectTask) // Timeout nach 5 Sek
                    {
                        Console.WriteLine($"❌ Timeout: {ipToScan.IPorHostname} reagiert nicht.");
                        socket.Close();
                        continue;
                    }

                    using (NetworkStream stream = new NetworkStream(socket, true))
                    {
                        byte[] smbNegotiationRequest = (dialect == SMBDialects._1)
                            ? GetSMB1NegotiationRequest()
                            : GetSMB2NegotiationRequest_Dialects(dialect);

                        await stream.WriteAsync(smbNegotiationRequest, 0, smbNegotiationRequest.Length);

                        byte[] tempResponse = new byte[1024];
                        var readTask = stream.ReadAsync(tempResponse, 0, tempResponse.Length);
                        if (await Task.WhenAny(readTask, Task.Delay(2000, _cts.Token)) != readTask) // Timeout für Response
                        {
                            Console.WriteLine($"⚠ Keine SMB-Antwort von {ipToScan.IPorHostname}");
                            continue;
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            byte[] response = new byte[bytesRead];
                            Array.Copy(tempResponse, response, bytesRead);

                            switch (dialect)
                            {
                                case SMBDialects._1:
                                    ipToScan.SMBVersions.Add("1.0");
                                    break;
                                case SMBDialects._2_0_2:
                                    ipToScan.SMBVersions.Add("2.0.2");
                                    break;
                                case SMBDialects._2_1:
                                    ipToScan.SMBVersions.Add("2.1");
                                    break;
                                case SMBDialects._3_0:
                                    ipToScan.SMBVersions.Add("3.0");
                                    break;
                                case SMBDialects._3_0_2:
                                    ipToScan.SMBVersions.Add("3.0.2");
                                    break;
                                case SMBDialects._3_1_1:
                                    ipToScan.SMBVersions.Add("3.1.1");
                                    break;
                                default:
                                    break;
                            }
                        }
                    }

                    socket.Shutdown(SocketShutdown.Both);
                    socket.Close();
                }
            }
            catch (SocketException se)
            {
                Console.WriteLine($"Socket error: {se.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to SMB server: {ex.Message}");
            }
        }

        if (ipToScan.SMBVersions.Count > 0)
        {
            int respondedValue = Interlocked.Increment(ref responded);
            await Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running),_cts.Token);

            Task.Run(() => SMBIPScanFinished?.Invoke(ipToScan)); // Event auslösen            
        }
    }



    private enum SMBDialects
    {
        _1,
        _2_0_2,
        _2_1,
        _3_0,
        _3_0_2,
        _3_1_1,
        all
    }

    private byte[] GetSMB1NegotiationRequest()
    {
        List<byte> smb1NegotiatePackage = new List<byte>();

        // NetBios Session Service
        smb1NegotiatePackage.Add(0x00); // Message Typ
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00, 0x31 }); // Length

        // SMB Header
        smb1NegotiatePackage.AddRange(new byte[] { 0xff, 0x53, 0x4d, 0x42 }); // Server Component
        smb1NegotiatePackage.Add(0x72); // SMB Command: Negotiate Protocol
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // NT Status
        smb1NegotiatePackage.Add(0x18); // Flags
        smb1NegotiatePackage.AddRange(new byte[] { 0x45, 0x68 }); // Flags2
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00 }); // ProcessID

        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Signature
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00 }); // Reserved
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00 }); // TreeID

        smb1NegotiatePackage.AddRange(new byte[] { 0xd7, 0x0c }); // ProcessID
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00 }); // UserID
        smb1NegotiatePackage.AddRange(new byte[] { 0x01, 0x00 }); // Multiplex

        // Negotiate Protocol Request
        smb1NegotiatePackage.Add(0x00); // WordCount WCT
        smb1NegotiatePackage.AddRange(new byte[] { 0x0e, 0x00 }); // ByteCount WCC

        // Requested Dialects
        smb1NegotiatePackage.Add(0x02); // BufferFormat: Dialect (2)

        smb1NegotiatePackage.AddRange(new byte[]
        {
        0x4e, 0x54, 0x20, 0x4c, // Name
        0x4d, 0x20, 0x30, 0x2e,
        0x31, 0x32, 0x00
        });

        // Dialect
        smb1NegotiatePackage.Add(0x02); // Buffer Format: Dialect (2)
        smb1NegotiatePackage.Add(0x00); // Name

        return smb1NegotiatePackage.ToArray();
    }

    private byte[] GetSMB2NegotiationRequest_Dialects(SMBDialects dialects)
    {
        List<byte> smbPacket = new List<byte>();

        // NetBios Session Service
        smbPacket.Add(0x00);            // Message Type

        if (dialects != SMBDialects.all)
        {
            smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x66 }); // Length
        }
        else
        {
            smbPacket.AddRange(new byte[] { 0x00, 0x00, 0xb4 }); // Length
        }

        // SMB Header
        smbPacket.AddRange(new byte[] { 0xfe, 0x53, 0x4d, 0x42 }); // Protocol ID
        smbPacket.AddRange(new byte[] { 0x40, 0x00 }); // Header Length
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Credit Charge
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Channel Sequence
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Reserved
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Command: Negotiate Protocol (0)
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Credits Request
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Flags
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Chain Offset

        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Message ID
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Reserved
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // TreeID

        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Session ID
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        // Signature
        smbPacket.AddRange(new byte[]
        {
            0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36
        });

        // Negotiate Protocol Request
        smbPacket.AddRange(new byte[] { 0x24, 0x00 }); // StructureSize

        if (dialects != SMBDialects.all)
        {
            smbPacket.AddRange(new byte[] { 0x01, 0x00 }); // DialectCount (1)
        }
        else
        {
            int dialectCount = Enum.GetValues(typeof(SMBDialects)).Length;
            smbPacket.AddRange(new byte[] { (byte)dialectCount, 0x00 }); // DialectCount (1)
        }

        smbPacket.Add(0x01); // SecurityMode
        smbPacket.Add(0x00); //unknown
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Reserved
        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Capabilities

        // ClientGUID
        smbPacket.AddRange(new byte[]
        {
            0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36
        });

        smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // NegotiateContextOffset
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // NegotiateContextCount
        smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // Reserved

        // Dialects (nur einer, weil DialectCount = 1)

        switch (dialects)
        {
            case SMBDialects._2_0_2:
                smbPacket.AddRange(new byte[] { 0x02, 0x02 }); // 2.0.2
                break;
            case SMBDialects._2_1:
                smbPacket.AddRange(new byte[] { 0x10, 0x02 }); // 2.1
                break;
            case SMBDialects._3_0:
                smbPacket.AddRange(new byte[] { 0x00, 0x03 }); // 3.0
                break;
            case SMBDialects._3_0_2:
                smbPacket.AddRange(new byte[] { 0x02, 0x03 }); // 3.0.2
                break;
            case SMBDialects._3_1_1:
                smbPacket.AddRange(new byte[] { 0x11, 0x03 }); // 3.1.1
                break;
            case SMBDialects.all:
                smbPacket.AddRange(new byte[] { 0x02, 0x02 }); // 2.0.2
                smbPacket.AddRange(new byte[] { 0x10, 0x02 }); // 2.1
                smbPacket.AddRange(new byte[] { 0x00, 0x03 }); // 3.0
                smbPacket.AddRange(new byte[] { 0x02, 0x03 }); // 3.0.2
                smbPacket.AddRange(new byte[] { 0x11, 0x03 }); // 3.1.1


                smbPacket.AddRange(new byte[] { 0x00, 0x00 }); // unknown

                // Negotiate Context Block 1
                smbPacket.AddRange(new byte[]
                {
                    0x02, 0x00,
                    0x06, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x02, 0x00,
                    0x02, 0x00,
                    0x01, 0x00,
                    0x00, 0x00
                });

                // Negotiate Context Block 2
                smbPacket.AddRange(new byte[]
                {
                    0x01, 0x00,
                    0x2c, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x02, 0x00,
                    0x02, 0x00,
                    0x01, 0x00,
                    0x01, 0x00,
                    0x20, 0x00
                });

                // Weiterer Datenblock
                smbPacket.AddRange(new byte[]
                {
                    0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                });
                break;
            default:
                break;
        }

        // Konvertieren zu byte[]
        return smbPacket.ToArray();
    }

    private ushort GetDialectCode(SMBDialects dialect)
    {
        return dialect switch
        {
            SMBDialects._2_0_2 => 0x0202,
            SMBDialects._2_1 => 0x0210,
            SMBDialects._3_0 => 0x0222,
            SMBDialects._3_0_2 => 0x0302,
            SMBDialects._3_1_1 => 0x0311,
            _ => 0
        };
    }


    private bool IsSMBVersionSupported(byte[] response)
    {
        if (response.Length < 74) return false; // Sicherstellen, dass die Antwort lang genug ist

        ushort dialect = BitConverter.ToUInt16(response, 72); // SMB-Dialekt-Position
        return Enum.GetValues(typeof(SMBDialects))
                   .Cast<SMBDialects>()
                   .Where(d => d != SMBDialects.all)
                   .Any(d => dialect == GetDialectCode(d));
    }
}

//public class SMBResponse
//{
//    public string IPAddress { get; set; }
//    public List<string> Versions { get; set; }

//    public override string ToString()
//    {
//        return $"SMB Response:\n" +
//               $"Scanned IP: {IPAddress}\n" +
//               $"Supported SMB Versions: {string.Join(", ", Versions)}";
//    }
//}



