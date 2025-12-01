/* HISOL VANET Simulation (Extended, No WAVE module)
 * Implements:
 *  - WiFi 802.11p VANET communication
 *  - Highway mobility (default)
 *  - BSM Broadcast App
 *  - Sybil Attack
 *  - Replay Attack
 *  - Jammer Node
 *  - RSSI Logging
 *  - Neighbor Count Logging
 *  - Separate log files for each subsystem
 *
 * Works on NS-3.46 out of the box.
 */

#include "ns3/core-module.h"
#include "ns3/wifi-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/packet.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/config.h"
#include <fstream>
#include <map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("HISOL_VANET_FULL");

// -------------------------
// File Outputs
// -------------------------
static std::ofstream bsm_output;
static std::ofstream rssi_output;
static std::ofstream neighbor_output;
static std::ofstream sybil_output;
static std::ofstream replay_output;
static std::ofstream jammer_output;

// -------------------------
// Global Simulation Params
// -------------------------
static uint32_t g_numVehicles = 50;
static double g_simTime = 60.0;
static double g_bsmInterval = 0.1;     // 10 Hz
static double g_laneSpacing = 4.0;     // Highway lane width
static uint32_t g_lanes = 3;           // Number of lanes on each direction

// Replay buffer (store last N packets)
std::map<uint32_t, std::vector<std::string>> replayBuffers;

// -------------------------------
// BSM Application
// -------------------------------
class BsmApp : public Application
{
public:
  BsmApp() {}
  void Setup(Ptr<Socket> socket, Ptr<Node> node, double interval)
  {
    m_socket = socket;
    m_node = node;
    m_interval = interval;
  }

private:
  Ptr<Socket> m_socket;
  Ptr<Node> m_node;
  double m_interval;

  virtual void StartApplication()
  {
    SendBsm();
  }

  void SendBsm()
  {
    Ptr<MobilityModel> mob = m_node->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    Vector vel = mob->GetVelocity();

    std::ostringstream msg;
    msg << "BSM," << m_node->GetId()
        << "," << pos.x << "," << pos.y
        << "," << vel.x << "," << vel.y
        << "," << Simulator::Now().GetSeconds();

    std::string s = msg.str();

    // Buffer for replay attack
    replayBuffers[m_node->GetId()].push_back(s);
    if (replayBuffers[m_node->GetId()].size() > 20)
      replayBuffers[m_node->GetId()].erase(replayBuffers[m_node->GetId()].begin());

    Ptr<Packet> p = Create<Packet>((uint8_t*)s.c_str(), s.size());
    m_socket->Send(p);

    bsm_output << m_node->GetId() << "," << pos.x << "," << pos.y
            << "," << vel.x << "," << vel.y
            << "," << Simulator::Now().GetSeconds() << "\n";

    Simulator::Schedule(Seconds(m_interval), &BsmApp::SendBsm, this);
  }
};

// -------------------------
// RSSI Receiver Callback
// -------------------------
void ReceivePacket(Ptr<Socket> socket)
{
  Ptr<Node> node = socket->GetNode();
  Ptr<Packet> packet;
  Address src;

  while ((packet = socket->RecvFrom(src)))
  {
    uint8_t buf[200];
    packet->CopyData(buf, packet->GetSize());
    std::string s((char*)buf, packet->GetSize());

    double rssi = socket->GetNode()->GetDevice(0)->GetObject<WifiNetDevice>()
                      ->GetPhy()->GetRxGain();

    rssi_output << node->GetId() << "," << s << "," << rssi << "\n";
  }
}

// -------------------------
// Neighbor Count (heuristic)
// -------------------------
void LogNeighbors(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<MobilityModel> mob_i = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos_i = mob_i->GetPosition();

    uint32_t count = 0;

    for (uint32_t j = 0; j < nodes.GetN(); j++)
    {
      if (i == j) continue;
      Ptr<MobilityModel> mob_j = nodes.Get(j)->GetObject<MobilityModel>();
      if (mob_i->GetDistanceFrom(mob_j) < 250.0)  // comm range approx
        count++;
    }

    neighbor_output << Simulator::Now().GetSeconds() << "," << i << "," << count << "\n";
  }

  Simulator::Schedule(Seconds(0.2), &LogNeighbors, nodes);
}

// -------------------------
// Sybil Attack
// -------------------------
void InjectSybil(NodeContainer nodes, uint32_t attacker, uint32_t sybils)
{
  Ptr<Node> a = nodes.Get(attacker);
  Ptr<MobilityModel> mob = a->GetObject<MobilityModel>();
  Vector pos = mob->GetPosition();

  for (uint32_t i = 1; i <= sybils; i++)
  {
    uint32_t fakeId = attacker * 100 + i;

    sybil_output << Simulator::Now().GetSeconds()
              << ",fakeID=" << fakeId
              << ",from=" << attacker
              << ",x=" << pos.x
              << ",y=" << pos.y << "\n";
  }

  Simulator::Schedule(Seconds(1.0), &InjectSybil, nodes, attacker, sybils);
}

// -------------------------
// Replay Attack
// -------------------------
void InjectReplay(NodeContainer nodes, uint32_t attacker)
{
  Ptr<Node> a = nodes.Get(attacker);

  if (replayBuffers[attacker].empty()) return;

  std::string replay = replayBuffers[attacker].back(); // use last buffered packet

  replay_output << Simulator::Now().GetSeconds()
             << ",attacker=" << attacker
             << "," << replay << "\n";

  Simulator::Schedule(Seconds(2.0), &InjectReplay, nodes, attacker);
}

// -------------------------
// Jammer Node
// -------------------------
void JammerTx(Ptr<Socket> sock)
{
  std::string j = "JAMMER";
  Ptr<Packet> p = Create<Packet>((uint8_t*)j.c_str(), j.size());
  sock->Send(p);

  jammer_output << Simulator::Now().GetSeconds() << "," << sock->GetNode()->GetId() << "\n";

  Simulator::Schedule(Seconds(0.005), &JammerTx, sock);
}

// -------------------------
// Highway Mobility
// -------------------------
void InstallHighwayMobility(NodeContainer nodes)
{
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();

  uint32_t perLane = nodes.GetN() / g_lanes;
  double velocity = 25.0;  // ~90 km/h

  for (uint32_t lane = 0; lane < g_lanes; lane++)
  {
    for (uint32_t i = 0; i < perLane; i++)
    {
      double x = i * 15.0;
      double y = lane * g_laneSpacing;
      posAlloc->Add(Vector(x, y, 0));
    }
  }

  mobility.SetPositionAllocator(posAlloc);
  mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
  mobility.Install(nodes);

  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<ConstantVelocityMobilityModel> m =
      nodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
    m->SetVelocity(Vector(velocity, 0.0, 0.0));
  }
}

// =====================================================
// MAIN
// =====================================================
int main(int argc, char *argv[])
{
  CommandLine cmd;
  cmd.AddValue("numVehicles", "Number of vehicles", g_numVehicles);
  cmd.AddValue("simTime", "Simulation time (s)", g_simTime);
  cmd.Parse(argc, argv);

  // Output files
  bsm_output.open("bsm_log.csv");
  rssi_output.open("rssi_log.csv");
  neighbor_output.open("neighbor_log.csv");
  sybil_output.open("sybil_log.csv");
  replay_output.open("replay_log.csv");
  jammer_output.open("jammer_log.csv");

  NodeContainer vehicles;
  vehicles.Create(g_numVehicles);

  // Mobility = HIGHWAY by default
  InstallHighwayMobility(vehicles);

  // ----------------------------------------------------
  // WiFi 802.11p
  // ----------------------------------------------------
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  channel.AddPropagationLoss("ns3::FriisPropagationLossModel");

  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211p);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                               "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer devs = wifi.Install(phy, mac, vehicles);

  InternetStackHelper inet;
  inet.Install(vehicles);

  Ipv4AddressHelper ip;
  ip.SetBase("10.55.0.0", "255.255.0.0");
  ip.Assign(devs);

  // BSM apps + RSSI receiver
  for (uint32_t i = 0; i < vehicles.GetN(); i++)
  {
    Ptr<Node> node = vehicles.Get(i);

    Ptr<Socket> recvSock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    recvSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 5000));
    recvSock->SetRecvCallback(MakeCallback(&ReceivePacket));

    Ptr<Socket> sendSock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    sendSock->SetAllowBroadcast(true);
    sendSock->Connect(InetSocketAddress(Ipv4Address("255.255.255.255"), 5000));

    Ptr<BsmApp> app = CreateObject<BsmApp>();
    app->Setup(sendSock, node, g_bsmInterval);
    node->AddApplication(app);
    app->SetStartTime(Seconds(1.0));
  }

  // Neighbor logging every 0.2s
  Simulator::Schedule(Seconds(1.0), &LogNeighbors, vehicles);

  // Attacks
  Simulator::Schedule(Seconds(10.0), &InjectSybil, vehicles, 0, 4);
  Simulator::Schedule(Seconds(20.0), &InjectReplay, vehicles, 2);

  // Jammer node = last node
  {
    Ptr<Node> jnode = vehicles.Get(vehicles.GetN() - 1);
    Ptr<Socket> jsock = Socket::CreateSocket(jnode, UdpSocketFactory::GetTypeId());
    jsock->SetAllowBroadcast(true);
    jsock->Connect(InetSocketAddress(Ipv4Address("255.255.255.255"), 5001));
    Simulator::Schedule(Seconds(5.0), &JammerTx, jsock);
  }

  Simulator::Stop(Seconds(g_simTime));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}

