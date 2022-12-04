using PacketDotNet;
using SharpPcap.LibPcap;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class QuicknDirty
    {
        //public partial class _Default : System.Web.UI.Page
        //{
        //    [DllImport("iphlpapi.dll", ExactSpelling = true)]
        //    public static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
        //    Finding Ip Address of a system.......(Jayant Tripathy tests........//
        //    public string SystemIpip()
        //    {
        //        string stringIpAddress;
        //        stringIpAddress = Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
        //        string stringHostName = Dns.GetHostEntry(Request.ServerVariables["REMOTE_ADDR"]).HostName;
        //        if (stringIpAddress == null)
        //            stringIpAddress = Request.ServerVariables["REMOTE_ADDR"];
        //        return stringIpAddress;
        //    }

        //    // Finding Mac Addree of a system.......(Jayant Tripathy tests........//
        //    private string GetMacUsingARP(string IPAddr)
        //    {
        //        IPAddress IP = IPAddress.Parse(IPAddr);
        //        byte[] macAddr = new byte[6];
        //        uint macAddrLen = (uint)macAddr.Length;
        //        if (SendARP((int)IP.Address, 0, macAddr, ref macAddrLen) != 0)
        //            throw new Exception("ARP command failed");
        //        string[] str = new string[(int)macAddrLen];
        //        for (int i = 0; i < macAddrLen; i++)
        //            str[i] = macAddr[i].ToString("x2");
        //        return string.Join("-", str);
        //    }
        //}
    }


  
      
    }
