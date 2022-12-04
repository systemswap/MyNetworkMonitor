using PacketDotNet.Utils;
using PacketDotNet;
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
using SharpPcap;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_SYN
    {
        public ScanningMethod_SYN()
        {
           
        }
        byte[] packet = null;

        //https://www.winsocketdotnetworkprogramming.com/clientserversocketnetworkcommunication8n.html
        //https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/


        private SharpPcap.CaptureDeviceList devices;
        public void SharpPCap(string sourceIP, int sourcePort, string destIP, int destPort)
        {
            //Generate a random packet
            EthernetPacket packet = EthernetPacket.RandomPacket();
            packet.SourceHardwareAddress = PhysicalAddress.Parse("C8E265A022C9");
            //packet.DestinationHardwareAddress = dstMacAddress;

            string ss = "Message TCP";
            byte[] bArray = System.Text.Encoding.ASCII.GetBytes(ss);
            byte[] asd = new byte[60];
            bArray.CopyTo(asd, 20);

            ByteArraySegment bas = new ByteArraySegment(asd);
            TcpPacket tcpPacket = new TcpPacket(bas);

            IPPacket ipPacket = IPPacket.RandomPacket(IPVersion.IPv4);
            ipPacket.TimeToLive = 20;
            ipPacket.Protocol = PacketDotNet.ProtocolType.Tcp;
            ipPacket.Version = IPVersion.IPv4;
            ipPacket.DestinationAddress = IPAddress.Parse(destIP);
            ipPacket.SourceAddress = IPAddress.Parse(sourceIP);
            ipPacket.PayloadPacket = tcpPacket;
            packet.PayloadPacket = ipPacket;
            ipPacket.ParentPacket = packet;
                        
            tcpPacket.SourcePort = Convert.ToUInt16(sourcePort);
            tcpPacket.DestinationPort = Convert.ToUInt16(destPort);
            tcpPacket.Synchronize = true;
            tcpPacket.WindowSize = 500;
            tcpPacket.AcknowledgmentNumber = 1000;
            tcpPacket.SequenceNumber = 1000;
            tcpPacket.DataOffset = TcpFields.HeaderLength + 1;
            tcpPacket.UpdateTcpChecksum();
            tcpPacket.ParentPacket = ipPacket;

            try
            {
                //Send the packet out the network device

                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();

                devices = CaptureDeviceList.Instance;


                devices[5].Open();
                devices[5].SendPacket(packet);
                //ScanManager.Instance.AddPacket(packet, IPProtocolType.TCP);
            }
            catch (Exception e)
            {
                Console.WriteLine("-- " + e.Message);
            }
        }
        
        
        //public async void SendSyn()
        //{
        //    //s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        //    Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);

        //    //s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        //    s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);


        //    try
        //    {
        //        IPEndPoint bindEndPoint = new IPEndPoint(IPAddress.Any, 53);
        //        //s.Bind(bindEndPoint);
        //        s.Send(SynPacket("192.168.178.5", "192.168.178.1", 39598, 53));
        //        s.Close();
        //    }
        //    catch (SocketException ex)
        //    {

        //        throw ex;
        //    }
           
        //}

        private byte[] SynPacket(string sourceIP, string destinationIP, int sourcePort, int destinationPort)
        {
            byte[] _sourceIP = IPAddress.Parse(sourceIP).GetAddressBytes();
            byte[] _destinationIP = IPAddress.Parse(destinationIP).GetAddressBytes();

            byte[] tada = BitConverter.GetBytes(sourcePort);
            byte[] _sourcePort = new byte[2];
            string _hex_sPort = sourcePort.ToString("X");
            _sourcePort = Enumerable.Range(0, _hex_sPort.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(_hex_sPort.Substring(x, 2), 16)).ToArray();

            byte[] _destinationPort = new byte[2];
            string _hex_dPort = destinationPort.ToString("X");
            _destinationPort = Enumerable.Range(0, _hex_dPort.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(_hex_dPort.Substring(x, 2), 16)).ToArray();


            string _hex_ipChecksum = "ec";
            byte[] _ipChecksum = new byte[2];
            _ipChecksum = Enumerable.Range(0, _hex_ipChecksum.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(_hex_ipChecksum.Substring(x, 2), 16)).ToArray();


            string _hex_tcpChecksum = "e632";
            byte[] _tcpChecksum = new byte[2];
            _tcpChecksum = Enumerable.Range(0, _hex_tcpChecksum.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(_hex_tcpChecksum.Substring(x, 2), 16)).ToArray();


            List<byte[]> ip_header = new List<byte[]>();
            List<byte[]> tcp_header = new List<byte[]>();
            //byte[] packet = null;

            //ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
            ip_header.Add(new byte[] { 0x45, 0x00, 0x00, 0x2c });

            //ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
            ip_header.Add(new byte[] { 0xf7, 0xa5, 0x00, 0x00 });

            //ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
            ip_header.Add(new byte[] { 0x28, 0x06 }.Concat(_ipChecksum).ToArray());

            //ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
            ip_header.Add(_sourceIP);

            //ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address
            ip_header.Add(_destinationIP);



            //tcp_header = b'\x30\x39\x00\x50' # Source Port | Destination Port
            tcp_header.Add(_sourcePort.Concat(_destinationPort).ToArray());

            //tcp_header += b'\x00\x00\x00\x00' # Sequence Number
            tcp_header.Add(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            //tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
            tcp_header.Add(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            //tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
            tcp_header.Add(new byte[] { 0x50, 0x02, 0x71, 0x10 });

            //tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer
            tcp_header.Add(_tcpChecksum.Concat(new byte[] { 0x00, 0x00 }).ToArray());


            //packet = ip_header + tcp_header
            packet = Enumerable.Concat(ip_header.SelectMany(bytes => bytes).ToArray(), tcp_header.SelectMany(bytes => bytes).ToArray()).ToArray();
            return packet;
        }



        
    }
}
