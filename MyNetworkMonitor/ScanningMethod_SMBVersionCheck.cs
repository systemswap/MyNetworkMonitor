
using System.Collections.Generic;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;

public class ScanningMethod_SMBVersionCheck
{
    public event Action<SMBResponse> SMBIPScanFinished;
    public event Action<int, int> SMBProgress;
    public event Action SMBScanFinished;

    public ScanningMethod_SMBVersionCheck()
    {

    }

    public async Task ScanMultipleIPsAsync(List<string> ipList, int port)
    {
        int total = ipList.Count;
        int completed = 0;

        var tasks = ipList.Select(async ip =>
        {
            var response = await CheckProtocolsAsync(ip, port);
            SMBProgress?.Invoke(++completed, total);
            return response;
        });

        await Task.WhenAll(tasks);

        SMBScanFinished?.Invoke();
    }

    private async Task<SMBResponse> CheckProtocolsAsync(string ipAddress, int port)
    {
        SMBResponse smbResponse = new SMBResponse { IPAddress = ipAddress, Versions = new List<string>() };

        foreach (SMBDialects dialect in Enum.GetValues(typeof(SMBDialects)))
        {

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                    socket.Connect(ipAddress, port);

                    using (NetworkStream stream = new NetworkStream(socket))
                    {
                        byte[] smbNegotiationRequest;
                        if (dialect == SMBDialects._1)
                        {
                            smbNegotiationRequest = GetSMB1NegotiationRequest();
                        }
                        else
                        {
                            smbNegotiationRequest = GetSMB2NegotiationRequest_Dialects(dialect);
                        }


                        stream.Write(smbNegotiationRequest, 0, smbNegotiationRequest.Length);
                        stream.Flush();

                        Thread.Sleep(100); // Kurze Wartezeit für Stabilität

                        byte[] tempResponse = new byte[1024];
                        int bytesRead = stream.Read(tempResponse, 0, tempResponse.Length);

                        //byte[] response = new byte[bytesRead];
                        //Array.Copy(tempResponse, response, bytesRead);

                        if (bytesRead > 0)
                        {
                            //var tada = ParseSMBResponse(response);
                            //tada.IPAddress = ipAddress;

                            byte[] response = new byte[bytesRead];
                            Array.Copy(tempResponse, response, bytesRead);

                            //if (dialect == SMBDialects._1)
                            //{ smbResponse.Versions.Add("1.0"); }

                            //if (IsSMBVersionSupported(response))
                            //{
                            //    smbResponse.Versions.Add(dialect.ToString().Replace("_", ".")); // Format als "2.0.2", "2.1" etc.
                            //}

                            switch (dialect)
                            {
                                case SMBDialects._1:
                                    smbResponse.Versions.Add("1.0");
                                    break;
                                case SMBDialects._2_0_2:
                                    smbResponse.Versions.Add("2.0.2");
                                    break;
                                case SMBDialects._2_1:
                                    smbResponse.Versions.Add("2.1");
                                    break;
                                case SMBDialects._3_0:
                                    smbResponse.Versions.Add("3.0");
                                    break;
                                case SMBDialects._3_0_2:
                                    smbResponse.Versions.Add("3.0.2");
                                    break;
                                case SMBDialects._3_1_1:
                                    smbResponse.Versions.Add("3.1.1");
                                    break;
                                case SMBDialects.all:
                                    smbResponse.Versions.Add("all");
                                    break;
                                default:
                                    break;
                            }
                        }
                        else
                        {
                            //Console.WriteLine("No response received from SMB server.");
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
        SMBIPScanFinished?.Invoke(smbResponse); // Event auslösen
        return smbResponse;
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

public class SMBResponse
{
    public string IPAddress { get; set; }
    public List<string> Versions { get; set; }

    public override string ToString()
    {
        return $"SMB Response:\n" +
               $"Scanned IP: {IPAddress}\n" +
               $"Supported SMB Versions: {string.Join(", ", Versions)}";
    }
}

