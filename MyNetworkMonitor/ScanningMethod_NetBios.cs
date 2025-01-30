using MyNetworkMonitor;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

//public class ScanResult
//{
//    public string IP { get; set; }
//    public string Hostname { get; set; }
//    public string Workgroup { get; set; }
//    public string MacAddress { get; set; } = "00-00-00-00-00-00";
//    public List<string> NameTypes { get; set; } = new List<string>();
//    public bool IsNetBiosActive { get; set; }
//    public string ErrorText { get; set; }
//}

public class ScanningMethod_NetBios
{
    public event Action<IPToScan> NetbiosIPScanFinished;
    //current, responsed, total
    public event Action<int, int, int> ProgressUpdated;
    public event Action<bool> NetbiosScanFinished;

    int current = 0;
    int responsed = 0;
    int total = 0;

    public async Task ScanMultipleIPsAsync(List<IPToScan> iPToScans, CancellationToken cancellationToken)
    {
        current = 0;
        responsed = 0;
        total = iPToScans.Count;

        await Parallel.ForEachAsync(iPToScans, cancellationToken, async (ip, token) =>
        {
            if (token.IsCancellationRequested)
                return; // Statt `break`, um parallele Tasks nicht abrupt zu beenden

            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(current, responsed, total);

            ip.UsedScanMethod = ScanMethod.NetBios;
            await QueryNetBiosAsync(ip, token);           
        });

        NetbiosScanFinished?.Invoke(true);
    }


    private async Task QueryNetBiosAsync(IPToScan iPToScan, CancellationToken cancellationToken)
    {
        
        try
        {
            if (GetRemoteNetBiosName(IPAddress.Parse(iPToScan.IPorHostname), out string nbName, out string nbDomain, out string macAddress))
            {
                iPToScan.NetBiosHostname = nbName;
                //result.Workgroup = nbDomain;
                //result.MacAddress = macAddress;
                //result.IsNetBiosActive = true;
            }
            else
            {
                //result.ErrorText = "Keine NetBIOS-Antwort erhalten.";
            }
        }
        catch (Exception ex)
        {
            //result.ErrorText = $"Fehler: {ex.Message}";
        }

        int responsedValue = Interlocked.Increment(ref responsed);
        ProgressUpdated?.Invoke(current, responsedValue, total);
        NetbiosIPScanFinished?.Invoke(iPToScan);
    }

    private static bool GetRemoteNetBiosName(IPAddress targetAddress, out string nbName, out string nbDomainOrWorkgroupName, out string macAddress, int receiveTimeOut = 5000, int retries = 1)
    {
        byte[] nameRequest = new byte[]{
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01 };

        do
        {
            byte[] receiveBuffer = new byte[1024];
            using Socket requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, receiveTimeOut);

            nbName = null;
            nbDomainOrWorkgroupName = null;
            macAddress = "00-00-00-00-00-00";

            EndPoint remoteEndpoint = new IPEndPoint(targetAddress, 137);
            IPEndPoint originEndpoint = new IPEndPoint(IPAddress.Any, 0);
            requestSocket.Bind(originEndpoint);
            requestSocket.SendTo(nameRequest, remoteEndpoint);
            try
            {
                int receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                if (receivedByteCount >= 90)
                {
                    Encoding enc = new ASCIIEncoding();
                    nbName = enc.GetString(receiveBuffer, 57, 15).Trim();
                    nbDomainOrWorkgroupName = enc.GetString(receiveBuffer, 75, 15).Trim();

                    // MAC-Adresse extrahieren (letzten 6 Bytes des NetBIOS-Statistikblocks)
                    int macOffset = receivedByteCount - 6;
                    if (macOffset > 0 && receivedByteCount >= macOffset + 6)
                    {
                        macAddress = BitConverter.ToString(receiveBuffer, macOffset, 6);
                    }
                    return true;
                }
            }
            catch (SocketException)
            {
                // Kein Antwort erhalten
            }
            retries--;
        } while (retries >= 0);

        return false;
    }
}
