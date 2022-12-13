using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace MyNetworkMonitor
{
    internal class Satellit_SocketServer
    {
        public Satellit_SocketServer()
        {

        }

        TcpListener myList;
        
        public void StartServer()
        {
            try
            {
                IPAddress ipAd = IPAddress.Parse("192.168.178.5");
                // use local m/c IP address, and 
                // use the same in the client

                /* Initializes the Listener */
                myList = new TcpListener(ipAd, 8443);
                //myList = new TcpListener(IPAddress.Any, 8443);

                /* Start Listening at the specified port */
                myList.Start();

                Debug.WriteLine("The server is running at port 8443...");
                Debug.WriteLine("The local End point is  :" +
                                  myList.LocalEndpoint);
                Debug.WriteLine("Waiting for a connection.....");

                Socket s = Task.Run(() => myList.AcceptSocketAsync()).Result;
                Debug.WriteLine("Connection accepted from " + s.RemoteEndPoint);

                byte[] b = new byte[342];
                //int k = s.Receive(b);


            
                var k = s.Receive(b);

                Debug.WriteLine("Recieved...");



                //for (int i = 0; i < k; i++)
                //    Debug.Write(Convert.ToChar(b[i]));

                Stream stream = new MemoryStream(b);
                IPToRefresh toRefresh1 = new IPToRefresh();
                XmlSerializer xmlSerializer= new XmlSerializer(toRefresh1.GetType());
                var test = xmlSerializer.Deserialize(stream);


                ASCIIEncoding asen = new ASCIIEncoding();
                s.Send(asen.GetBytes("The string was recieved by the server."));
                Debug.WriteLine("\nSent Acknowledgement");
                s.Close();
                myList.Stop();
            }
            catch (Exception e)
            {
                Debug.WriteLine("Error..... " + e.StackTrace);
            }
        }

        public void StopServer()
        {
            myList.Stop();
        }
    }
}
