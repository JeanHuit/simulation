#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ns2-mobility-helper.h"

using namespace ns3;

// -----------------------------------------------------
// Simple periodic broadcaster (BSM-like)
// -----------------------------------------------------
class BsmApp : public Application
{
public:
  BsmApp() : m_socket(0), m_packetSize(200), m_interval(Seconds(0.1)) {}

  void Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, Time interval)
  {
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;
    m_interval = interval;
  }

private:
  virtual void StartApplication() override
  {
    m_socket->SetAllowBroadcast(true);
    m_socket->Bind();
    m_sendEvent = Simulator::Schedule(Seconds(0.1), &BsmApp::SendPacket, this);
  }

  virtual void StopApplication() override
  {
    if (m_sendEvent.IsPending())   // FIXED: use IsPending()
      Simulator::Cancel(m_sendEvent);

    if (m_socket)
      m_socket->Close();
  }

  void SendPacket()
  {
    Ptr<Packet> packet = Create<Packet>(m_packetSize);
    m_socket->SendTo(packet, 0, m_peer);

    m_sendEvent = Simulator::Schedule(m_interval, &BsmApp::SendPacket, this);
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  uint32_t m_packetSize;
  Time m_interval;
  EventId m_sendEvent;
};

// -----------------------------------------------------
// Main Simulation
// -----------------------------------------------------
int main(int argc, char *argv[])
{
  uint32_t numNodes = 132;  // Nodes 0..131 from mobility.tcl
  std::string mobilityFile = "/home/jeanhuit/Documents/Workspace/simulation/roads-sumo/2025-12-05-21-50-47/mobility.tcl";

  // Create nodes
  NodeContainer nodes;
  nodes.Create(numNodes);

  // Load SUMO mobility
  Ns2MobilityHelper ns2(mobilityFile);
  ns2.Install(nodes.Begin(), nodes.End());

  // ------------------------
  // WiFi (802.11p-like)
  // ------------------------
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211p);

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();

  YansWifiPhyHelper phy;     // FIXED: no ::Default()
  phy.SetChannel(channel.Create());
  phy.Set("TxPowerStart", DoubleValue(20));
  phy.Set("TxPowerEnd", DoubleValue(20));

  wifi.SetRemoteStationManager(
      "ns3::ConstantRateWifiManager",
      "DataMode", StringValue("OfdmRate6Mbps"),
      "ControlMode", StringValue("OfdmRate6Mbps")
  );

  NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

  // Internet
  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.0.0", "255.255.0.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

  // ------------------------
  // Install BSM app
  // ------------------------
  uint16_t port = 4000;

  for (uint32_t i = 0; i < numNodes; ++i)
  {
    Ptr<Node> node = nodes.Get(i);
    Ptr<Socket> sock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    Address broadcast = InetSocketAddress(Ipv4Address("255.255.255.255"), port);

    Ptr<BsmApp> app = CreateObject<BsmApp>();
    app->Setup(sock, broadcast, 200, Seconds(0.1));
    node->AddApplication(app);
    app->SetStartTime(Seconds(1.0));
    app->SetStopTime(Seconds(30.0));  // Match the simulation time
  }

  // NetAnim
  AnimationInterface anim("vanet.xml");
  anim.SetMobilityPollInterval(Seconds(1.0));  // Increased from 0.25 to reduce trace data
  // Reduce node positions saved to prevent large trace files
  anim.EnablePacketMetadata(false);  // Disable packet metadata to reduce file size


  Simulator::Stop(Seconds(30.0));  // Reduced from 1910.0 for testing
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}
