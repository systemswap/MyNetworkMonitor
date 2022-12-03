using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_SYN
    {
        public ScanningMethod_SYN()
        {
           
        }
        byte[] packet = null;

        //https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
        public async void SendSyn()
        {
            //s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);

            //s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            

            

            //s.sendto(packet, ('10.10.10.1', 0))
            s.SendToAsync(SynPacket(), new IPEndPoint(IPAddress.Parse("192.168.178.5"), 53));
            s.Close();            
        }

        private byte[] SynPacket()
        {
            List<byte[]> ip_header = new List<byte[]>();
            List<byte[]> tcp_header = new List<byte[]>();
            //byte[] packet = null;

            //ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
            ip_header.Add(new byte[] { 0x45, 0x00, 0x00, 0x28 });

            //ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
            ip_header.Add(new byte[] { 0x45, 0x00, 0x00, 0x28 });

            //ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
            ip_header.Add(new byte[] { 0xab, 0xcd, 0x00, 0x00 });

            //ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
            ip_header.Add(new byte[] { 0x40, 0x06, 0xa6, 0xec });

            //ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
            ip_header.Add(new byte[] { 0x0a, 0x0a, 0x0a, 0x02 });

            //ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address
            ip_header.Add(new byte[] { 0x0a, 0x0a, 0x0a, 0x01 });



            //tcp_header = b'\x30\x39\x00\x50' # Source Port | Destination Port
            tcp_header.Add(new byte[] { 0x30, 0x39, 0x00, 0x50 });

            //tcp_header += b'\x00\x00\x00\x00' # Sequence Number
            tcp_header.Add(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            //tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
            tcp_header.Add(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            //tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
            tcp_header.Add(new byte[] { 0x50, 0x02, 0x71, 0x10 });

            //tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer
            tcp_header.Add(new byte[] { 0xe6, 0x32, 0x00, 0x00 });


            //packet = ip_header + tcp_header
            packet = Enumerable.Concat(ip_header.SelectMany(bytes => bytes).ToArray(), tcp_header.SelectMany(bytes => bytes).ToArray()).ToArray();
            return packet;
        }



        public void SynScan(string IP, int Port, bool PerformRST = false)
        {
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {                    
                    socket.Connect(new IPEndPoint(IPAddress.Parse(IP), Port));

                    //Debug.WriteLine("Connected to server.");

                    //set the lingerstate to perform a reset
                    if (PerformRST)
                    {
                        socket.LingerState = new LingerOption(true, 0);
                    }
                    else
                    {
                        socket.Close();
                    }
                }
                catch (SocketException ex)
                {
                    //ex.ErrorCode 
                    //10013 Ausgehende Verbindung Blockiert durch Firewall
                    //10060 Host nicht erreichbar, Zeitüberschreitung
                    //10061 Host verweigert zugriff
                    throw ex;
                }
            }
        }


        public void SynScanAsync(string IP, int Port, TimeSpan timeout)
        {
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    IAsyncResult ar = socket.BeginConnect(new IPEndPoint(IPAddress.Parse(IP), Port), null, null);
                    ar.AsyncWaitHandle.WaitOne(timeout.Milliseconds, true);
                    if (ar.IsCompleted)
                    {
                        //Connected
                        socket.LingerState = new LingerOption(true, 0);
                    }
                    else
                    {
                        socket.Close();
                        throw new SocketException(10060); // Connection timed out.
                    }
                }
                catch (SocketException ex)
                {
                    //ex.ErrorCode 
                    //10013 Ausgehende Verbindung Blockiert durch Firewall
                    //10060 Host nicht erreichbar, Zeitüberschreitung
                    //10061 Host verweigert zugriff
                    throw ex;
                }
            }
        }
    }
}
