using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WindowsAPI
{
    public class DNS
    {
        /// <summary>
        /// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms682082(v=vs.85).aspx
        /// </summary>
        #region DLL Imports

        [DllImport("dnsapi",  CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern int DnsQuery_W([MarshalAs(UnmanagedType.LPWStr)] string pszName, DnsRecordType wType, QueryOption options, ref IP4_ARRAY dnsServerIpArray, ref IntPtr ppQueryResults, int pReserved);

        [DllImport("dnsapi", CharSet = CharSet.Auto, SetLastError = true)]
        static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);

        enum QueryOption
        {
            DNS_QUERY_STANDARD = 0,
            DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 1,
            DNS_QUERY_USE_TCP_ONLY = 2,
            DNS_QUERY_NO_RECURSION = 4,
            DNS_QUERY_BYPASS_CACHE = 8,
            DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
            DNS_QUERY_NO_HOSTS_FILE = 0x40,
            DNS_QUERY_NO_LOCAL_NAME = 0x20,
            DNS_QUERY_NO_NETBT = 0x80,
            DNS_QUERY_NO_WIRE_QUERY = 0x10,
            DNS_QUERY_RESERVED = -16777216,
            DNS_QUERY_RETURN_MESSAGE = 0x200,
            DNS_QUERY_TREAT_AS_FQDN = 0x1000,
            DNS_QUERY_WIRE_ONLY = 0x100
        }

        enum DnsRecordType : short
        {
            DNS_TYPE_A = 1,
            DNS_TYPE_NS = 2,
            DNS_TYPE_CNAME = 5,
            DNS_TYPE_SOA = 6,
            DNS_TYPE_PTR = 12,
            DNS_TYPE_HINFO = 13,
            DNS_TYPE_MX = 15,
            DNS_TYPE_TXT = 16,
            DNS_TYPE_AAAA = 28
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CNAMERecord
        {
            // Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public DnsRecordType wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;

            // CANME record specific
            public IntPtr pNameHost;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MXRecord
        {
            // Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public DnsRecordType wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;

            // MX record specific
            public IntPtr pNameExchange;
            public short wPreference;
            public short Pad;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TXTRecord
        {
            // Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public DnsRecordType wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;

            // MX record specific
            public int dwStringCount;
            public IntPtr pStringArray;

        }

        public struct IP4_ARRAY
        {
            public UInt32 AddrCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)] public UInt32[] AddrArray;
        }
        #endregion



        public static string GetCNAMERecord(string domain, string[] serverIP = null)
        {
            IntPtr recordsArray = IntPtr.Zero;
            IntPtr dnsRecord = IntPtr.Zero;
            CNAMERecord cnameRecord;
            IP4_ARRAY dnsServerArray = new IP4_ARRAY();

            if (serverIP != null && serverIP.Length > 0)
            {
                dnsServerArray.AddrCount = (uint)(serverIP.Length);
                dnsServerArray.AddrArray = new uint[serverIP.Length];

                for (int C = 0; C < serverIP.Length; C++)
                {
                    IPAddress iPAddress;

                    if (IPAddress.TryParse(serverIP[C], out iPAddress))
                    {
                        dnsServerArray.AddrCount++;
                        uint address = BitConverter.ToUInt32(iPAddress.GetAddressBytes(), 0);
                        dnsServerArray.AddrArray[C] = address;
                    }
                }

            }


            // Interop calls will only work on Windows platform (no mono c#)
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException();
            }

            try
            {
                int queryResult = DnsQuery_W(domain, DnsRecordType.DNS_TYPE_CNAME, QueryOption.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, 0);

                // Check for error
                if (queryResult != 0)
                {
                    throw new Win32Exception(queryResult);
                }

                // Loop through the result record list
                for (dnsRecord = recordsArray; !dnsRecord.Equals(IntPtr.Zero); dnsRecord = cnameRecord.pNext)
                {
                    cnameRecord = (CNAMERecord)Marshal.PtrToStructure(dnsRecord, typeof(CNAMERecord));
                    if (cnameRecord.wType == DnsRecordType.DNS_TYPE_CNAME)
                    {
                        string txt = Marshal.PtrToStringAuto(cnameRecord.pNameHost);
                        return txt==null?"":txt;
                    }
                }
            }
            finally
            {
                DnsRecordListFree(recordsArray, 0);
            }
            return "";
        }
        public static List<string> GetMXRecords(string domain, string[] serverIP = null)
        {
            IntPtr ppResults = IntPtr.Zero;
            MXRecord mxRecord;
            IP4_ARRAY dnsServerArray = new IP4_ARRAY();

            if (serverIP != null && serverIP.Length>0)
            {

                dnsServerArray.AddrCount = (uint)(serverIP.Length);
                dnsServerArray.AddrArray = new uint[serverIP.Length];

                for (int C = 0; C < serverIP.Length; C++)
                {
                    IPAddress iPAddress;

                    if (IPAddress.TryParse(serverIP[C], out iPAddress))
                    {
                        dnsServerArray.AddrCount++;
                        uint address = BitConverter.ToUInt32(iPAddress.GetAddressBytes(), 0);
                        dnsServerArray.AddrArray[C] = address;
                    }
                }

            }
            var results = new List<Tuple<short, string>>();
            int error = DnsQuery_W(domain, DnsRecordType.DNS_TYPE_MX, QueryOption.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref ppResults, 0);
            if (error != 0)
                throw new Win32Exception(error);

            for (var pRecord = ppResults; pRecord != IntPtr.Zero; pRecord = mxRecord.pNext)
            {
                mxRecord = (MXRecord)Marshal.PtrToStructure(pRecord, typeof(MXRecord));
                if (mxRecord.wType == DnsRecordType.DNS_TYPE_MX)
                {
                    string name = Marshal.PtrToStringAuto(mxRecord.pNameExchange);
                    results.Add(new Tuple<short, string>(mxRecord.wPreference, name));
                }
            }

            DnsRecordListFree(ppResults, 0);

            return results.OrderBy(x => x.Item1).Select(x => x.Item2).ToList();
        }
        public static List<string> GetTXTRecords(string domain, string[] serverIP = null)
        {
            IntPtr recordsArray = IntPtr.Zero;
            IntPtr dnsRecord = IntPtr.Zero;
            TXTRecord txtRecord;
            IP4_ARRAY dnsServerArray = new IP4_ARRAY();

            if (serverIP != null && serverIP.Length>0)
            {
                dnsServerArray.AddrCount = 0;
                dnsServerArray.AddrArray = new uint[serverIP.Length];

                for(int C=0; C<serverIP.Length;C++)
                {

                    IPAddress iPAddress;
                        
                    if(IPAddress.TryParse(serverIP[C],out iPAddress))
                    {
                        dnsServerArray.AddrCount++;
                        uint address = BitConverter.ToUInt32(iPAddress.GetAddressBytes(), 0);
                        dnsServerArray.AddrArray[C] = address;
                    }

                        
                    

                }
              
            }

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException();
            }

            var results = new List<string>();
            try
            {
                int queryResult = DnsQuery_W(domain, DnsRecordType.DNS_TYPE_TXT, QueryOption.DNS_QUERY_BYPASS_CACHE,ref dnsServerArray, ref recordsArray, 0);

                if (queryResult != 0)
                {
                    throw new Win32Exception(queryResult);
                }

                for (dnsRecord = recordsArray; !dnsRecord.Equals(IntPtr.Zero); dnsRecord = txtRecord.pNext)
                {
                    txtRecord = (TXTRecord)Marshal.PtrToStructure(dnsRecord, typeof(TXTRecord));
                    if (txtRecord.wType == DnsRecordType.DNS_TYPE_TXT)
                    {
                        string txt = Marshal.PtrToStringAuto(txtRecord.pStringArray);
                        results.Add(txt);
                    }
                }
            }
            finally
            {
                DnsRecordListFree(recordsArray, 0);
            }
            return results;
        }



        

    }
}
