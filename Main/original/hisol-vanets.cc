/* HISOL VANET Simulation (No WAVE module)
 * Uses WiFi configured for 802.11p (10 MHz OFDM mode)
 * Works on NS-3.46 out of the box.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include <fstream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("HISOLVANET_NO_WAVE");

static std::ofstream output_log;

// Simulation parameters
static uint32_t g_numVehicles = 50;
static double g_simTime = 60.0;
static double g_bsmInterval = 0.1;

// ----------------------------------------------------------------------
// BSM Application
// ----------------------------------------------------------------------
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
    Ptr<Packet> p = Create<Packet>((uint8_t*)s.c_str(), s.size());
    m_socket->Send(p);

    // Log to CSV
    output_log << m_node->GetId() << "," << pos.x << "," << pos.y
          << "," << vel.x << "," << vel.y
          << "," << Simulator::Now().GetSeconds()
          << "\n";

    Simulator::Schedule(Seconds(m_interval), &BsmApp::SendBsm, this);
  }
};

// ----------------------------------------------------------------------
// HISOL Attack Hooks (Placeholders)
// ----------------------------------------------------------------------
void InjectGpsSpoof(NodeContainer nodes, uint32_t nodeId, Vector offset)
{
  NS_LOG_UNCOND("GPS spoof on node " << nodeId);
  Ptr<MobilityModel> mob = nodes.Get(nodeId)->GetObject<MobilityModel>();
  Vector p = mob->GetPosition();
  mob->SetPosition(Vector(p.x + offset.x, p.y + offset.y, p.z + offset.z));
}

void InjectSybil(NodeContainer nodes, uint32_t attacker)
{
  NS_LOG_UNCOND("Sybil attack triggered by node " << attacker);
  // Implement ML-side fake BSM generation if needed.
}

void InjectJamming(YansWifiPhyHelper& phy)
{
  NS_LOG_UNCOND("Jamming ON");
  phy.Set("RxNoiseFigure", DoubleValue(100.0)); // crude jammer
}

// ----------------------------------------------------------------------
// MAIN
// ----------------------------------------------------------------------
int main(int argc, char *argv[])
{
  CommandLine cmd;
  cmd.AddValue("numVehicles", "Number of vehicles", g_numVehicles);
  cmd.AddValue("simTime", "Simulation time (s)", g_simTime);
  cmd.AddValue("bsmInterval", "BSM interval (s)", g_bsmInterval);
  cmd.Parse(argc, argv);

  output_log.open("bsm_log.csv");
  output_log << "node,x,y,vx,vy,time\n";

  // Create nodes
  NodeContainer vehicles;
  vehicles.Create(g_numVehicles);

  // Mobility: simple grid + motion
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> allocator = CreateObject<ListPositionAllocator>();

  int grid = std::ceil(std::sqrt(g_numVehicles));
  double spacing = 20.0;

  for (uint32_t i = 0; i < g_numVehicles; i++)
    allocator->Add(Vector((i % grid) * spacing, (i / grid) * spacing, 0));

  mobility.SetPositionAllocator(allocator);
  mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
  mobility.Install(vehicles);

  for (uint32_t i = 0; i < g_numVehicles; i++)
  {
    Ptr<ConstantVelocityMobilityModel> m =
      vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>();

    double vx = 4.0 + (i % 3);
    m->SetVelocity(Vector(vx, 0.0, 0.0));
  }

  // -----------------------------------------------------
  // WiFi configured as 802.11p (10 MHz channels)
  // -----------------------------------------------------
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211p); // Use correct 802.11p standard
  wifi.SetRemoteStationManager(
      "ns3::ConstantRateWifiManager",
      "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
      "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));

  WifiMacHelper mac;   // simple ad-hoc MAC
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer devices = wifi.Install(phy, mac, vehicles);

  // IP stack
  InternetStackHelper inet;
  inet.Install(vehicles);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.0.0", "255.255.0.0");
  ipv4.Assign(devices);

  // -----------------------------------------------------
  // Install BSM apps
  // -----------------------------------------------------
  for (uint32_t i = 0; i < g_numVehicles; i++)
  {
    Ptr<Node> node = vehicles.Get(i);

    Ptr<Socket> receiver = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    InetSocketAddress any = InetSocketAddress(Ipv4Address::GetAny(), 5000);
    receiver->Bind(any);

    Ptr<Socket> sender = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    InetSocketAddress broadcast = InetSocketAddress(Ipv4Address("255.255.255.255"), 5000);
    sender->SetAllowBroadcast(true);
    sender->Connect(broadcast);

    Ptr<BsmApp> app = CreateObject<BsmApp>();
    app->Setup(sender, node, g_bsmInterval);
    node->AddApplication(app);
    app->SetStartTime(Seconds(1.0));
  }

  // -----------------------------------------------------
  // Schedule sample attacks
  // -----------------------------------------------------
  Simulator::Schedule(Seconds(12), &InjectGpsSpoof, vehicles, 0, Vector(30, 10, 0));
  Simulator::Schedule(Seconds(18), &InjectSybil, vehicles, 2);
  Simulator::Schedule(Seconds(25), &InjectJamming, phy);

  Simulator::Stop(Seconds(g_simTime));
  Simulator::Run();
  Simulator::Destroy();

  output_log.close();
  return 0;
}
