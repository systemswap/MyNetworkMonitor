using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace MyNetworkMonitor
{
    internal class SendReceiveDataUDP
    {
        //https://gist.github.com/louis-e/888d5031190408775ad130dde353e0fd

        public class UDPSocket
        {
            public Socket _socket;
            private const int bufSize = 8 * 1024;
            private State state = new State();
            private EndPoint epFrom = new IPEndPoint(IPAddress.Any, 0);
            private AsyncCallback recv = null;

            public class State
            {
                public byte[] buffer = new byte[bufSize];
            }

            public void Server(string address, int port)
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.ReuseAddress, true);
                _socket.Bind(new IPEndPoint(IPAddress.Parse(address), port));
                Receive();
            }

            public void Client(string address, int port)
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _socket.Connect(IPAddress.Parse(address), port);
                Receive();
            }

            public void Send(string text)
            {
                byte[] data = Encoding.ASCII.GetBytes(text);
                _socket.BeginSend(data, 0, data.Length, SocketFlags.None, (ar) =>
                {
                    State so = (State)ar.AsyncState;
                    int bytes = _socket.EndSend(ar);
                    Console.WriteLine("SEND: {0}, {1}", bytes, text);
                }, state);
            }

            private void Receive()
            {
                _socket.BeginReceiveFrom(state.buffer, 0, bufSize, SocketFlags.None, ref epFrom, recv = (ar) =>
                {
                    try
                    {
                        State so = (State)ar.AsyncState;
                        int bytes = _socket.EndReceiveFrom(ar, ref epFrom);
                        _socket.BeginReceiveFrom(so.buffer, 0, bufSize, SocketFlags.None, ref epFrom, recv, so);
                        Console.WriteLine("RECV: {0}: {1}, {2}", epFrom.ToString(), bytes, Encoding.ASCII.GetString(so.buffer, 0, bytes));
                    }
                    catch { }

                }, state);
            }
        }




        public class SimpleSample
        {
            private async Task<int> SendRecaive_via_UDP(string IP, int port)
            {
                try
                {

                    // This constructor arbitrarily assigns the local port number.
                    UdpClient udpClient = new UdpClient(port);
                    try
                    {
                        udpClient.Connect(IP, port);

                        // Sends a message to the host to which you have connected.
                        Byte[] sendBytes = Encoding.ASCII.GetBytes("Is anybody there?");

                        udpClient.Send(sendBytes, sendBytes.Length);

                        //IPEndPoint object will allow us to read datagrams sent from any source.
                        IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);

                        // Blocks until a message returns on this socket from a remote host.
                        Byte[] receiveBytes = udpClient.Receive(ref RemoteIpEndPoint);
                        string returnData = Encoding.ASCII.GetString(receiveBytes);

                        // Uses the IPEndPoint object to determine which of these two hosts responded.
                        Debug.WriteLine("This is the message you received " +
                                                     returnData.ToString());
                        Debug.WriteLine("This message was sent from " +
                                                    RemoteIpEndPoint.Address.ToString() +
                                                    " on their port number " +
                                                    RemoteIpEndPoint.Port.ToString());

                        udpClient.Close();
                        //udpClientB.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.ToString());
                    }


                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Error Port: {port} {e.Message}");
                }
                return -1;
            }
        }
    }
}
