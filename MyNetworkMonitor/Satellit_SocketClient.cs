using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Interop;
using System.Xml.Serialization;

namespace MyNetworkMonitor
{
    internal class Satellit_SocketClient
    {

        public Satellit_SocketClient()
        {

        }

        TcpClient tcpclnt;

        //https://social.msdn.microsoft.com/Forums/en-US/ae005637-65fc-482f-bfee-267e85f709d1/how-to-send-an-object-through-network-using-tcp-sockets?forum=netfxnetcom
        public void StartClient()
        {
            try
            {
                tcpclnt = new TcpClient();
                Debug.WriteLine("Connecting.....");

                tcpclnt.Connect("192.168.178.5", 8443);
                // use the ipaddress as in the server program

                Debug.WriteLine("Connected");
                Debug.Write("Enter the string to be transmitted : ");

                String str = "nothing less then the network domination pinky, nothing less!";
                Stream stm = tcpclnt.GetStream();

                ASCIIEncoding asen = new ASCIIEncoding();
                byte[] ba = asen.GetBytes(str);
                Debug.WriteLine("Transmitting.....");

                //stm.Write(ba, 0, ba.Length);

                IPToRefresh toRefresh = new IPToRefresh();
                toRefresh.IPGroupDescription = "tada";

                XmlSerializer x = new XmlSerializer(toRefresh.GetType());

                MemoryStream stream = new MemoryStream();
                x.Serialize(stream, toRefresh);
                string buffer = Encoding.ASCII.GetString(stream.GetBuffer());
                Byte[] inputToBeSent = System.Text.Encoding.ASCII.GetBytes(buffer.ToCharArray());
                stm.Write(inputToBeSent, 0, inputToBeSent.Length);
                stm.Flush();

                //byte[] bb = new byte[100];
                //int k = stm.Read(bb, 0, 100);

                //for (int i = 0; i < k; i++)
                //    Debug.Write(Convert.ToChar(bb[i]));

                tcpclnt.Close();
            }

            catch (Exception e)
            {
                Debug.WriteLine("Error..... " + e.StackTrace);
            }
        }


        public void CloseClientConnection()
        {
            if (tcpclnt != null)
            {
                tcpclnt.Close();
            }
        }

    }
}
