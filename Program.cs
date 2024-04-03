using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Newtonsoft.Json;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace PacketSniffer
{
    class Program
    {
        private static Dictionary<string, int> synCount = new Dictionary<string, int>();

        private const int SynThreshold = 20;

        private static readonly object synCountLock = new object();

        private static Dictionary<string, int> udpPacketCounts = new Dictionary<string, int>();

        private const int UdpFloodThreshold = 20;

        private static Dictionary<string, int> icmpPacketCounts = new Dictionary<string, int>();

        private const int IcmpFloodThreshold = 20;

        private static int totalTcpPackets = 0;
        private static int totalUdpPackets = 0;
        private static int totalIcmpPackets = 0;
        private static int totalBlockedPackets = 0;

        private static HashSet<string> blacklistedIps = new HashSet<string>();

        static void Main()
        {
            Thread cleanupThread = new Thread(CleanupSynCount);
            cleanupThread.IsBackground = true;
            cleanupThread.Start();

            Thread liveUpdateThread = new Thread(LiveUpdate);
            liveUpdateThread.IsBackground = true;
            liveUpdateThread.Start();

            PacketDevice selectedDevice = LivePacketDevice.AllLocalMachine
                .Where(device => device.Description.Contains("Realtek PCIe 2.5GbE Family Controller"))
                .FirstOrDefault();

            if (selectedDevice != null)
            {
                PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);
                communicator.SetFilter("ip");
                communicator.ReceivePackets(0, PacketHandler);

            }
            else
            {
                Console.WriteLine("No suitable network interface found.");
            }
        }

        private static PacketDevice GetDeviceByGuid(string guid)
        {
            foreach (PacketDevice device in LivePacketDevice.AllLocalMachine)
            {
                Console.WriteLine(device.Description);
                if (device.Description.Contains(guid))
                {
                    return device;
                }
            }

            return null;
        }

        private static void CleanupSynCount()
        {
            while (true)
            {
                Thread.Sleep(1000); 

                lock (synCountLock)
                {
                    synCount = new Dictionary<string, int>(synCount);
                    foreach (var key in synCount.Keys)
                    {
                        if (synCount[key] <= 0)
                            synCount.Remove(key);
                    }
                }
            }
        }

        private static void BlockIp(string ip)
        {
            Console.WriteLine($"Blocking {ip}");
            totalBlockedPackets++;

            blacklistedIps.Add(ip);

            SaveBlacklistToJson();
        }

        private static void SaveBlacklistToJson()
        {
            File.WriteAllText("blacklist.json", JsonConvert.SerializeObject(blacklistedIps));
        }

        private static void LiveUpdate()
        {
           string banner = @"

  ▄    ▄▄▄▄▄▄▄    ▄
 ▀▀▄ ▄█████████▄ ▄▀▀
     ██ ▀███▀ ██
   ▄ ▀████▀████▀ ▄
 ▀█    ██▀█▀██    █▀


";
            while (true)
            {
                Console.Clear();
                Console.WriteLine("\u001b[33m" + banner + "\u001b[0m"); // Yellow text for banner
                Console.WriteLine($"TCP Packets: \u001b[32m{DisplayLivePackets(totalTcpPackets)}\u001b[0m UDP Packets: \u001b[34m{DisplayLivePackets(totalUdpPackets)}\u001b[0m ICMP Packets: \u001b[36m{DisplayLivePackets(totalIcmpPackets)}\u001b[0m");

                Console.WriteLine($"\nTotal Blocked Packets: \u001b[31m{totalBlockedPackets}\u001b[0m");

                Thread.Sleep(1000);
            }


        }

        private static string DisplayLivePackets(int totalPackets)
        {
            return $"Total: {totalPackets}";
        }

        private static void PacketHandler(Packet packet)
        {
            if (packet.Ethernet.IpV4 == null)
                return;

            string srcIp = packet.Ethernet.IpV4.Source.ToString();

            lock (synCountLock)
            {
                if (blacklistedIps.Contains(srcIp))
                {
                    return; 
                }

                if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Tcp &&
                    packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Synchronize) &&
                    !packet.Ethernet.IpV4.Tcp.ControlBits.HasFlag(TcpControlBits.Acknowledgment))
                {
                    if (!synCount.ContainsKey(srcIp))
                        synCount[srcIp] = 0;

                    synCount[srcIp]++;

                    if (synCount[srcIp] > SynThreshold)
                    {
                        BlockIp(srcIp);
                        return; 
                    }
                }
            }

            if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Udp)
            {
                string udpSrcIp = packet.Ethernet.IpV4.Source.ToString();
                string udpDstPort = packet.Ethernet.IpV4.Udp.DestinationPort.ToString();


                if (blacklistedIps.Contains(udpSrcIp))
                {
                    return; 
                }


                if (!udpPacketCounts.ContainsKey(udpSrcIp))
                    udpPacketCounts[udpSrcIp] = 0;

                udpPacketCounts[udpSrcIp]++;

                if (udpPacketCounts[udpSrcIp] > UdpFloodThreshold)
                {

                }
            }

            if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.InternetControlMessageProtocol)
            {
                string icmpSrcIp = packet.Ethernet.IpV4.Source.ToString();

                if (blacklistedIps.Contains(icmpSrcIp))
                {
                    return; 
                }

                icmpPacketCounts.TryGetValue(icmpSrcIp, out var icmpCount);
                icmpCount++;
                icmpPacketCounts[icmpSrcIp] = icmpCount;

                if (icmpCount > IcmpFloodThreshold)
                {
                    return; 
                }
            }

            if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Tcp)
            {
                string tcpSrcIp = packet.Ethernet.IpV4.Source.ToString();
                string tcpDstPort = packet.Ethernet.IpV4.Tcp.DestinationPort.ToString();


                if (blacklistedIps.Contains(tcpSrcIp))
                {
                    return; 
                }
                totalTcpPackets++;
            }

            if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Udp)
            {
                totalUdpPackets++;
            }
            else if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.InternetControlMessageProtocol)
            {
                totalIcmpPackets++;
            }
        }
    }
}
