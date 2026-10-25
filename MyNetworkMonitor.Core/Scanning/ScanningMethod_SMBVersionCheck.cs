// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor

using System.Collections.Generic;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using MyNetworkMonitor;
using System.Net;
using System.Collections.Concurrent;

/// <summary>
/// Determines which SMB dialects (1.0, 2.0.2 to 3.1.1) the targets accept on port 445.
/// </summary>
public class ScanningMethod_SMBVersionCheck
{
    /// <summary>Reports progress as (processed, responded, total, status).</summary>
    public event Action<int, int, int, ScanStatus> ProgressUpdated;

    /// <summary>Raised for every target that accepted at least one dialect.</summary>
    public event Action<IPToScan> SMBIPScanFinished;    

    /// <summary>Raised when all targets of a run have been checked.</summary>
    public event Action SMBScanFinished;


    /// <summary>Creates the SMB dialect check.</summary>
    public ScanningMethod_SMBVersionCheck()
    {

    }



    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource(); 
  

    /// <summary>
    /// Cancels the running check and reports <see cref="ScanStatus.stopped"/>.
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

        ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // Resets the progress display.
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
    /// Checks every target for each SMB dialect and reports the accepted dialects.
    /// </summary>
    /// <param name="IPsToScan">The targets; each entry must be an IPv4 address.</param>
    public async Task ScanMultipleIPsAsync(List<IPToScan> IPsToScan)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;
        int port = 445; // SMB port (direct hosting over TCP)

        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = 20, // At most 20 concurrent SMB requests
            CancellationToken = _cts.Token
        };

       

        int maxDegreeOfParallelism = 50;
        using var semaphore = new SemaphoreSlim(maxDegreeOfParallelism);
        var tasks = new List<Task>();

        foreach (var ipToScan in IPsToScan)
        {
            if (_cts.Token.IsCancellationRequested) break;

            await semaphore.WaitAsync(_cts.Token); // Wait for a free slot.
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (_cts.Token.IsCancellationRequested) return;

                    ipToScan.UsedScanMethod = ScanMethod.SMB;                

                    // Check the SMB dialects, each with its own time limit.
                    await CheckProtocolsAsync(ipToScan, port);
                }
                finally
                {
                    semaphore.Release();
                }
            }, _cts.Token));
        }

        // Wait for all checks before raising the event.
        await Task.WhenAll(tasks.Where(t => t != null));
       
        SMBScanFinished?.Invoke();
    }




    /// <summary>
    /// Counts the progress when the target has been checked completely, not when the check
    /// starts; otherwise the progress bar would be full while the answers for the individual
    /// dialects are still pending.
    /// </summary>
    private async Task CheckProtocolsAsync(IPToScan ipToScan, int port)
    {
        try
        {
            await CheckProtocolsCoreAsync(ipToScan, port);
        }
        finally
        {
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);
        }
    }

    private async Task CheckProtocolsCoreAsync(IPToScan ipToScan, int port)
    {
        foreach (SMBDialects dialect in Enum.GetValues(typeof(SMBDialects)))
        {
            if (_cts.Token.IsCancellationRequested) return;

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

                    var connectTask = socket.ConnectAsync(IPAddress.Parse(ipToScan.IPorHostname), port);
                    if (await Task.WhenAny(connectTask, Task.Delay(5000, cts.Token)) != connectTask) // Timeout after 5 s
                    {
                        Console.WriteLine($"Timeout: {ipToScan.IPorHostname} does not respond.");
                        socket.Close();
                        continue;
                    }

                    using (NetworkStream stream = new NetworkStream(socket, true))
                    {
                        byte[] smbNegotiationRequest = (dialect == SMBDialects._1)
                            ? GetSMB1NegotiationRequest()
                            : GetSMB2NegotiationRequest_Dialects(dialect);

                        await stream.WriteAsync(smbNegotiationRequest, 0, smbNegotiationRequest.Length, cts.Token);

                        byte[] tempResponse = new byte[1024];
                        var readTask = stream.ReadAsync(tempResponse, 0, tempResponse.Length, cts.Token);
                        if (await Task.WhenAny(readTask, Task.Delay(2000, cts.Token)) != readTask) // Timeout for the answer
                        {
                            Console.WriteLine($"No SMB answer from {ipToScan.IPorHostname}");
                            continue;
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0 && NegotiationSucceeded(tempResponse, bytesRead, dialect))
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

                    // No Shutdown/Close here: NetworkStream(socket, true) has already closed the
                    // socket on leaving the using block. Either call on the disposed socket throws
                    // "Cannot access a disposed object", which the catch clause below would log as
                    // a connection error although the answer has already been evaluated.
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
            ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

            SMBIPScanFinished?.Invoke(ipToScan);            
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

    /// <summary>
    /// Whether the answer really says "this dialect is supported" rather than only "something
    /// came back".
    /// <para>
    /// A Samba server with SMB1 disabled still answers an SMB1 request, with STATUS_SUCCESS and
    /// WordCount 1 but DialectIndex 0xFFFF, the documented value for "none of the offered
    /// dialects is supported" (MS-CIFS 2.2.4.52.2). Without this check every answer counts as a
    /// hit, including the explicit refusal. See docs/FEHLERGEDAECHTNIS.md, No. 3.
    /// </para>
    /// <para>
    /// For SMB2/3 the same applies to the Status field of the 64-byte header (MS-SMB2 2.2.1):
    /// 0 means accepted, any other value, usually STATUS_NOT_SUPPORTED, means refused. Against
    /// the same server an accepted 2.0.2 request returned status 0.
    /// </para>
    /// </summary>
    private static bool NegotiationSucceeded(byte[] response, int length, SMBDialects dialect)
    {
        if (dialect == SMBDialects._1)
        {
            // NetBIOS session header (4) + SMB1 header (32) + WordCount (1) = offset 37, where the
            // 2-byte DialectIndex is stored as a little-endian word.
            if (length < 39) return false;
            if (response[4] != 0xFF || response[5] != 0x53 || response[6] != 0x4D || response[7] != 0x42) return false;

            byte wordCount = response[36];
            if (wordCount < 1) return false;

            ushort dialectIndex = (ushort)(response[37] | (response[38] << 8));
            return dialectIndex != 0xFFFF;
        }

        // SMB2/3: NetBIOS session header (4) + Status field at offset 8 of the SMB2 header, so
        // absolute offset 12, 4 bytes.
        if (length < 16) return false;
        if (response[4] != 0xFE || response[5] != 0x53 || response[6] != 0x4D || response[7] != 0x42) return false;

        return response[12] == 0 && response[13] == 0 && response[14] == 0 && response[15] == 0;
    }

    private byte[] GetSMB1NegotiationRequest()
    {
        List<byte> smb1NegotiatePackage = new List<byte>();

        // Transport header of direct TCP on port 445 ([MS-SMB2] 2.1): one zero
        // byte, then the length in 3 bytes. For lengths below 64 KiB it is byte
        // for byte the NetBIOS session message of RFC 1002, section 4.3.1
        // (type, flags, 16-bit length).
        smb1NegotiatePackage.Add(0x00); // Message type
        smb1NegotiatePackage.AddRange(new byte[] { 0x00, 0x00, 0x31 }); // Length

        // SMB header (MS-CIFS 2.2.3.1)
        smb1NegotiatePackage.AddRange(new byte[] { 0xff, 0x53, 0x4d, 0x42 }); // Protocol: 0xFF 'SMB'
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

        // Negotiate Protocol request (MS-CIFS 2.2.4.52.1)
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

        // Transport header of direct TCP, as above ([MS-SMB2] 2.1)
        smbPacket.Add(0x00);            // Message Type

        if (dialects != SMBDialects.all)
        {
            smbPacket.AddRange(new byte[] { 0x00, 0x00, 0x66 }); // Length
        }
        else
        {
            smbPacket.AddRange(new byte[] { 0x00, 0x00, 0xb4 }); // Length
        }

        // SMB2 header (MS-SMB2 2.2.1)
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

        // SMB2 NEGOTIATE request (MS-SMB2 2.2.3)
        smbPacket.AddRange(new byte[] { 0x24, 0x00 }); // StructureSize

        if (dialects != SMBDialects.all)
        {
            smbPacket.AddRange(new byte[] { 0x01, 0x00 }); // DialectCount (1)
        }
        else
        {
            int dialectCount = Enum.GetValues(typeof(SMBDialects)).Length;
            smbPacket.AddRange(new byte[] { (byte)dialectCount, 0x00 }); // DialectCount
        }

        smbPacket.Add(0x01); // SecurityMode
        smbPacket.Add(0x00); // Second byte of SecurityMode
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

        // Dialects: one for a single dialect (DialectCount = 1), all five for SMBDialects.all.

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

                // Further data block
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

        // Convert to byte[].
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
        if (response.Length < 74) return false; // The answer must be long enough.

        ushort dialect = BitConverter.ToUInt16(response, 72); // Position of the SMB dialect
        return Enum.GetValues(typeof(SMBDialects))
                   .Cast<SMBDialects>()
                   .Where(d => d != SMBDialects.all)
                   .Any(d => dialect == GetDialectCode(d));
    }
}




