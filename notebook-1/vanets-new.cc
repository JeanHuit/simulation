/* VANET Simulation with Attack Mitigation
 * Implements:
 *  - WiFi 802.11p VANET communication
 *  - Multiple attacks: DDoS, Sybil, Replay, Jamming, Message Falsification
 *  - Mitigation techniques: Trust-based, ML-based, Hybrid, Rule-based
 *  - Detailed logging for analysis
 *  - ML Features as specified in data.txt
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
#include <algorithm>
#include <set>
#include <cmath>
#include <queue>
#include <limits>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VANET_ATTACK_MITIGATION");

// -------------------------
// File Outputs
// -------------------------
static std::ofstream bsm_output;
static std::ofstream attack_output;  // Comprehensive attack logs
static std::ofstream mitigation_output;  // Mitigation logs
static std::ofstream trust_output;   // Trust system logs
static std::ofstream ml_output;      // ML-based detection logs
static std::ofstream neighbor_output; // Neighbor logs
static std::ofstream jammer_output;  // Jamming logs
static std::ofstream sybil_output;   // Sybil logs
static std::ofstream ddos_output;    // DDoS logs
static std::ofstream msg_falsification_output; // Message falsification logs
static std::ofstream replay_output;  // Replay logs
static std::ofstream rssi_output;    // RSSI logs
static std::ofstream features_output; // ML features output
static std::ofstream detection_output; // Detection results output

// -------------------------
// Global Simulation Params
// -------------------------
static uint32_t g_numVehicles = 132;   // Using same as original
static double g_simTime = 30.0;        // Match our test version
static double g_bsmInterval = 0.1;     // 10 Hz
// Attack parameters
static bool g_enable_ddos = true;
static bool g_enable_sybil = true;
static bool g_enable_replay = true;
static bool g_enable_jamming = true;
static bool g_enable_msg_falsification = true;
// Mitigation parameters
static bool g_enable_trust = true;
static bool g_enable_ml = true;
static bool g_enable_hybrid = true;
static bool g_enable_rule = true;

// Attack/Node tracking
std::map<uint32_t, std::vector<std::string>> replayBuffers;  // For replay attacks
std::set<uint32_t> ddosNodes;
std::set<uint32_t> sybilNodes;
std::set<uint32_t> jammerNodes;
std::set<uint32_t> falsifiedNodes;

// Trust system
std::map<uint32_t, double> nodeTrust; // Trust scores for each node
std::map<uint32_t, std::vector<double>> trustHistory; // Track trust over time

// ML-based detection
std::map<uint32_t, std::vector<double>> mobilityHistory; // Store position history
std::map<uint32_t, int> suspiciousCount; // Suspicious behavior count

// Rule-based detection
std::map<uint32_t, int> packetFreqCount; // Track packet frequency per node
std::map<uint32_t, std::vector<Time>> packetTimestamps; // Track timestamps

// Feature collection for ML
struct BeaconFeatures {
  Vector position;           // claimed_position (x,y)
  Vector velocity;           // speed, heading
  Time timestamp;           // timestamp
  uint32_t neighborCount;   // neighbor_count (last window)
  double distanceToNearestNeighbor; // distance_to_nearest_neighbor
  double interArrivalTime;  // inter_arrival_time for messages from same src
  double packetRate;        // packet_rate (pkts/s)
  double avgPayloadSize;    // average payload size
  double positionDelta;     // position_delta (claimed vs. expected path)
  double speedDelta;        // speed_delta between GPS and inertial estimate
  int clusterSize;          // clustering of identities (for Sybil detection)

  BeaconFeatures() : position(0,0,0), velocity(0,0,0), neighborCount(0),
                     distanceToNearestNeighbor(0), interArrivalTime(0),
                     packetRate(0), avgPayloadSize(0), positionDelta(0),
                     speedDelta(0), clusterSize(0) {}
};

// Per-node feature tracking
std::map<uint32_t, std::queue<BeaconFeatures>> nodeFeatures;
std::map<uint32_t, std::vector<Time>> nodeMessageTimes; // for inter-arrival calculation
std::map<uint32_t, std::vector<double>> nodePayloadSizes; // for average payload calculation

// -------------------------------
// Enhanced BSM Application with Attack Capabilities
// -------------------------------
class EnhancedBsmApp : public Application
{
public:
  EnhancedBsmApp() : m_socket(0), m_node(0), m_attackType("none"), m_isAttacker(false) {}
  
  void Setup(Ptr<Socket> socket, Ptr<Node> node, double interval, std::string attackType = "none", bool isAttacker = false)
  {
    m_socket = socket;
    m_node = node;
    m_interval = interval;
    m_attackType = attackType;
    m_isAttacker = isAttacker;
  }

private:
  Ptr<Socket> m_socket;
  Ptr<Node> m_node;
  double m_interval;
  std::string m_attackType;
  bool m_isAttacker;

  virtual void StartApplication()
  {
    SendBsm();
  }

  void SendBsm()
  {
    Ptr<MobilityModel> mob = m_node->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    Vector vel = mob->GetVelocity();

    // Calculate features for ML
    BeaconFeatures features;
    features.position = pos;
    features.velocity = vel;
    features.timestamp = Simulator::Now();

    // Calculate speed
    double speed = sqrt(vel.x*vel.x + vel.y*vel.y);

    // Calculate heading (in radians)
    double heading = atan2(vel.y, vel.x);

    // Add to message times for inter_arrival calculation
    nodeMessageTimes[m_node->GetId()].push_back(Simulator::Now());
    if (nodeMessageTimes[m_node->GetId()].size() > 100) {
      nodeMessageTimes[m_node->GetId()].erase(nodeMessageTimes[m_node->GetId()].begin());
    }

    // Calculate inter arrival time
    if (nodeMessageTimes[m_node->GetId()].size() >= 2) {
      Time lastTime = nodeMessageTimes[m_node->GetId()].back();
      Time secondLastTime = *(nodeMessageTimes[m_node->GetId()].end() - 2);
      features.interArrivalTime = (lastTime - secondLastTime).GetSeconds();
    }

    // Add to payload size history (assuming fixed size for now)
    double payloadSize = 200.0; // Fixed size for this simulation
    nodePayloadSizes[m_node->GetId()].push_back(payloadSize);
    if (nodePayloadSizes[m_node->GetId()].size() > 50) {
      nodePayloadSizes[m_node->GetId()].erase(nodePayloadSizes[m_node->GetId()].begin());
    }

    // Calculate average payload size
    if (!nodePayloadSizes[m_node->GetId()].empty()) {
      double sum = 0;
      for (double size : nodePayloadSizes[m_node->GetId()]) {
        sum += size;
      }
      features.avgPayloadSize = sum / nodePayloadSizes[m_node->GetId()].size();
    }

    // Create BSM with additional fields for attack detection
    std::ostringstream msg;
    msg << "BSM," << m_node->GetId()
        << "," << pos.x << "," << pos.y
        << "," << vel.x << "," << vel.y
        << "," << Simulator::Now().GetSeconds();

    std::string s = msg.str();

    // Handle attacks if this is an attacker node
    if (m_isAttacker)
    {
      if (m_attackType == "ddos")
      {
        // DDoS: send multiple packets in rapid succession
        for (int i = 0; i < 10; i++) { // Send 10 packets at once
          Ptr<Packet> p = Create<Packet>((const uint8_t*)s.c_str(), s.length());
          m_socket->Send(p);

          ddos_output << Simulator::Now().GetSeconds()
                    << "," << m_node->GetId()
                    << ",ddos_attack," << i << "\n";
        }
      }
      else if (m_attackType == "sybil")
      {
        // Sybil: send with multiple fake IDs
        for (int i = 1; i <= 5; i++) { // Create 5 fake identities
          uint32_t fakeId = m_node->GetId() * 1000 + i;
          std::ostringstream fakeMsg;
          fakeMsg << "BSM," << fakeId
                  << "," << (pos.x + i*10) << "," << (pos.y + i*10)  // Slightly different positions
                  << "," << vel.x << "," << vel.y
                  << "," << Simulator::Now().GetSeconds();

          std::string fakeS = fakeMsg.str();
          Ptr<Packet> p = Create<Packet>((const uint8_t*)fakeS.c_str(), fakeS.length());
          m_socket->Send(p);

          sybil_output << Simulator::Now().GetSeconds()
                     << "," << fakeId
                     << "," << m_node->GetId()
                     << "," << (pos.x + i*10) << "," << (pos.y + i*10) << "\n";
        }
      }
      else if (m_attackType == "replay")
      {
        // Replay: send buffered packets from the past
        if (!replayBuffers[m_node->GetId()].empty()) {
          std::string replayMsg = replayBuffers[m_node->GetId()].back();
          Ptr<Packet> p = Create<Packet>((const uint8_t*)replayMsg.c_str(), replayMsg.length());
          m_socket->Send(p);

          replay_output << Simulator::Now().GetSeconds()
                      << "," << m_node->GetId()
                      << "," << replayMsg << "\n";
        }
      }
      else if (m_attackType == "falsification")
      {
        // Message falsification: send false position/velocity data
        std::ostringstream fakeMsg;
        fakeMsg << "BSM," << m_node->GetId()
                << "," << (pos.x + 500) << "," << (pos.y + 500)  // Falsified position
                << "," << (vel.x * 2) << "," << (vel.y * 2)      // Falsified velocity
                << "," << Simulator::Now().GetSeconds();

        std::string fakeS = fakeMsg.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)fakeS.c_str(), fakeS.length());
        m_socket->Send(p);

        msg_falsification_output << Simulator::Now().GetSeconds()
                               << "," << m_node->GetId()
                               << "," << (pos.x + 500) << "," << (pos.y + 500) << "\n";
      }
      else
      {
        // Normal packet transmission
        Ptr<Packet> p = Create<Packet>((const uint8_t*)s.c_str(), s.length());
        m_socket->Send(p);
      }
    }
    else
    {
      // Normal packet transmission
      Ptr<Packet> p = Create<Packet>((const uint8_t*)s.c_str(), s.length());
      m_socket->Send(p);
    }

    // Buffer for replay attack (for all nodes, so attackers can replay)
    replayBuffers[m_node->GetId()].push_back(s);
    if (replayBuffers[m_node->GetId()].size() > 50) // Keep last 50 packets
      replayBuffers[m_node->GetId()].erase(replayBuffers[m_node->GetId()].begin());

    // Log the BSM
    bsm_output << m_node->GetId() << "," << pos.x << "," << pos.y
            << "," << vel.x << "," << vel.y
            << "," << Simulator::Now().GetSeconds() << "\n";

    // Store features for ML
    nodeFeatures[m_node->GetId()].push(features);
    if (nodeFeatures[m_node->GetId()].size() > 100) { // Keep last 100 features
      nodeFeatures[m_node->GetId()].pop();
    }

    // Log features if we have enough data
    if (nodeFeatures[m_node->GetId()].size() == 1) { // Log first feature
      BeaconFeatures& f = nodeFeatures[m_node->GetId()].front();
      features_output << m_node->GetId() << ","
                    << f.position.x << "," << f.position.y << ","
                    << speed << "," << heading << ","
                    << f.timestamp.GetSeconds() << ","
                    << f.interArrivalTime << ","
                    << f.avgPayloadSize << "\n";
    }

    // Schedule next transmission
    Simulator::Schedule(Seconds(m_interval), &EnhancedBsmApp::SendBsm, this);
  }
};

// -------------------------
// Trust-based Mitigation System
// -------------------------
double calculateTrustScore(uint32_t nodeId, Vector pos, Vector vel, Time timestamp)
{
  double trust = 1.0; // Start with high trust

  // Check if position is physically plausible
  if (nodeId < g_numVehicles * 0.8) { // Only check for real vehicles, not sybil
    if (vel.x > 50.0 || vel.y > 50.0) { // Unusually high speed
      trust -= 0.3;
    }
    if (vel.x < 0 || vel.y < 0) { // Could be OK depending on direction
      trust -= 0.1;
    }
  }

  // Add to trust history
  trustHistory[nodeId].push_back(trust);
  if (trustHistory[nodeId].size() > 100) { // Only keep recent history
    trustHistory[nodeId].erase(trustHistory[nodeId].begin());
  }

  // Calculate average trust over time
  double avgTrust = trust;
  if (!trustHistory[nodeId].empty()) {
    double sum = 0;
    for (double t : trustHistory[nodeId]) {
      sum += t;
    }
    avgTrust = sum / trustHistory[nodeId].size();
  }

  return avgTrust;
}

// Update trust scores
void UpdateTrustScores(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<MobilityModel> mob = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    Vector vel = mob->GetVelocity();
    
    double trust = calculateTrustScore(i, pos, vel, Simulator::Now());
    
    // Update global trust score
    nodeTrust[i] = trust;
    
    // Log trust score
    trust_output << Simulator::Now().GetSeconds() 
                << "," << i 
                << "," << trust 
                << "," << (trust < 0.5 ? 1 : 0)  // Flag if low trust
                << "\n";
  }

  Simulator::Schedule(Seconds(1.0), &UpdateTrustScores, nodes);
}

// -------------------------
// ML-based Detection (Simple Anomaly Detection)
// -------------------------
bool detectAnomaly(uint32_t nodeId, Vector pos, Vector vel)
{
  // Simple ML-based detection: check for anomalous behavior
  bool isAnomaly = false;
  
  // Check if velocity is outside normal bounds
  double speed = sqrt(vel.x*vel.x + vel.y*vel.y);
  if (speed > 40.0) { // More than 40 m/s (~90 mph) is suspicious
    isAnomaly = true;
    suspiciousCount[nodeId]++;
  }
  
  // Check if position changed too much since last reading
  if (!mobilityHistory[nodeId].empty() && mobilityHistory[nodeId].size() >= 4) {
    // Compare current and previous positions
    // This is a simplified check
    if (speed > 35.0) { // High speed movement
      isAnomaly = true;
      suspiciousCount[nodeId]++;
    }
  }
  
  // Store current position for future comparisons
  mobilityHistory[nodeId] = {pos.x, pos.y, vel.x, vel.y};
  
  return isAnomaly;
}

void RunMLDetection(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<MobilityModel> mob = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    Vector vel = mob->GetVelocity();
    
    bool isAnomaly = detectAnomaly(i, pos, vel);
    
    if (isAnomaly) {
      ml_output << Simulator::Now().GetSeconds() 
               << "," << i 
               << ",anomaly_detected," << suspiciousCount[i] 
               << "\n";
    }
  }
  
  Simulator::Schedule(Seconds(0.5), &RunMLDetection, nodes);
}

// -------------------------
// Rule-based Detection
// -------------------------
bool checkRuleBased(uint32_t nodeId)
{
  // Rule 1: Check packet frequency
  // If a node sends too many packets in a short time window, flag as suspicious
  Time now = Simulator::Now();
  std::vector<Time>& timestamps = packetTimestamps[nodeId];
  
  // Keep only recent timestamps (last 0.5 seconds)
  auto it = timestamps.begin();
  while (it != timestamps.end()) {
    if ((now - *it).GetSeconds() > 0.5) {
      it = timestamps.erase(it);
    } else {
      ++it;
    }
  }
  
  // If more than 15 packets in 0.5 seconds, likely DDoS
  if (timestamps.size() > 15) {
    return true; // Suspicious
  }
  
  return false; // Not suspicious
}

void UpdateRuleBasedDetection(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    bool isSuspicious = checkRuleBased(i);
    
    if (isSuspicious) {
      // Log rule-based detection
      // We'll track this in the mitigation log
      mitigation_output << Simulator::Now().GetSeconds()
                      << "," << i
                      << ",rule_based_detection,high_frequency"
                      << "\n";
    }
  }
  
  Simulator::Schedule(Seconds(0.1), &UpdateRuleBasedDetection, nodes);
}

// -------------------------
// Hybrid Detection (Combining multiple approaches)
// -------------------------
void RunHybridDetection(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<MobilityModel> mob = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    Vector vel = mob->GetVelocity();
    
    bool mlAnomaly = detectAnomaly(i, pos, vel);
    bool ruleSuspicious = checkRuleBased(i);
    double trustScore = nodeTrust[i];
    
    // Hybrid detection: flag if any method detects an issue AND trust is low
    if ((mlAnomaly || ruleSuspicious) && trustScore < 0.6) {
      mitigation_output << Simulator::Now().GetSeconds()
                      << "," << i
                      << ",hybrid_detection,ml_anomaly=" << mlAnomaly 
                      << ",rule_violation=" << ruleSuspicious
                      << ",trust_score=" << trustScore
                      << "\n";
    }
  }
  
  Simulator::Schedule(Seconds(0.2), &RunHybridDetection, nodes);
}

// -------------------------
// RSSI Receiver Callback with Attack Detection
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

    // Parse the received BSM for analysis
    size_t pos1 = s.find(',');
    size_t pos2 = s.find(',', pos1 + 1);
    if (pos1 != std::string::npos && pos2 != std::string::npos) {
      std::string msgType = s.substr(0, pos1);
      std::string nodeIdStr = s.substr(pos1 + 1, pos2 - pos1 - 1);
      uint32_t nodeId = std::stoi(nodeIdStr);
      
      // Update packet frequency for rule-based detection
      packetTimestamps[nodeId].push_back(Simulator::Now());
      packetFreqCount[nodeId]++;
    }

    // Log RSSI information (placeholder)
    double rssi = -1.0; // Placeholder - actual RSSI requires detailed channel model
    rssi_output << node->GetId() << "," << s << "," << rssi << "\n";
  }
}

// -------------------------
// Neighbor Count (heuristic) with distance to nearest neighbor
// -------------------------
void LogNeighbors(NodeContainer nodes)
{
  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
    Ptr<MobilityModel> mob_i = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos_i = mob_i->GetPosition();

    uint32_t count = 0;
    double minDistance = std::numeric_limits<double>::max();

    for (uint32_t j = 0; j < nodes.GetN(); j++)
    {
      if (i == j) continue;
      Ptr<MobilityModel> mob_j = nodes.Get(j)->GetObject<MobilityModel>();
      double distance = mob_i->GetDistanceFrom(mob_j);

      if (distance < 250.0) {  // Communication range approx
        count++;
      }

      // Track minimum distance
      if (distance < minDistance) {
        minDistance = distance;
      }
    }

    neighbor_output << Simulator::Now().GetSeconds() << "," << i << "," << count << "," << minDistance << "\n";

    // Update features with neighbor information
    if (nodeFeatures.find(i) != nodeFeatures.end() && !nodeFeatures[i].empty()) {
      BeaconFeatures& f = nodeFeatures[i].back();  // Get last feature
      f.neighborCount = count;
      f.distanceToNearestNeighbor = minDistance;
    }
  }

  Simulator::Schedule(Seconds(0.2), &LogNeighbors, nodes);
}

// -------------------------
// Attack Injection Functions
// -------------------------
void InjectDdosAttack(NodeContainer nodes, uint32_t attacker)
{
  if (g_enable_ddos) {
    ddosNodes.insert(attacker);
    ddos_output << Simulator::Now().GetSeconds() 
              << "," << attacker 
              << ",attack_started,ddos" << "\n";
  }
  Simulator::Schedule(Seconds(5.0), &InjectDdosAttack, nodes, attacker);
}

void InjectSybilAttack(NodeContainer nodes, uint32_t attacker)
{
  if (g_enable_sybil) {
    sybilNodes.insert(attacker);
    sybil_output << Simulator::Now().GetSeconds() 
               << "," << attacker 
               << ",attack_started,sybil" << "\n";
  }
  Simulator::Schedule(Seconds(7.0), &InjectSybilAttack, nodes, attacker);
}

void InjectReplayAttack(NodeContainer nodes, uint32_t attacker)
{
  if (g_enable_replay) {
    replay_output << Simulator::Now().GetSeconds() 
                << "," << attacker 
                << ",attack_started,replay" << "\n";
  }
  Simulator::Schedule(Seconds(10.0), &InjectReplayAttack, nodes, attacker);
}

void InjectJammerNode(Ptr<Socket> sock, uint32_t nodeId)
{
  if (g_enable_jamming) {
    jammerNodes.insert(nodeId);
    std::string j = "JAMMING_SIGNAL";
    Ptr<Packet> p = Create<Packet>((const uint8_t*)j.c_str(), j.length());
    sock->Send(p);

    jammer_output << Simulator::Now().GetSeconds() << "," << nodeId << ",jamming_active\n";

    Simulator::Schedule(Seconds(0.001), &InjectJammerNode, sock, nodeId); // High frequency jamming
  }
}

void InjectMsgFalsification(NodeContainer nodes, uint32_t attacker)
{
  if (g_enable_msg_falsification) {
    falsifiedNodes.insert(attacker);
    msg_falsification_output << Simulator::Now().GetSeconds() 
                           << "," << attacker 
                           << ",attack_started,falsification" << "\n";
  }
  Simulator::Schedule(Seconds(12.0), &InjectMsgFalsification, nodes, attacker);
}

// =====================================================
// MAIN
// =====================================================
int main(int argc, char *argv[])
{
  CommandLine cmd;
  cmd.AddValue("numVehicles", "Number of vehicles", g_numVehicles);
  cmd.AddValue("simTime", "Simulation time (s)", g_simTime);
  cmd.AddValue("enable_ddos", "Enable DDoS attack", g_enable_ddos);
  cmd.AddValue("enable_sybil", "Enable Sybil attack", g_enable_sybil);
  cmd.AddValue("enable_replay", "Enable Replay attack", g_enable_replay);
  cmd.AddValue("enable_jamming", "Enable Jamming attack", g_enable_jamming);
  cmd.AddValue("enable_msg_falsification", "Enable Message Falsification", g_enable_msg_falsification);
  cmd.AddValue("enable_trust", "Enable Trust-based mitigation", g_enable_trust);
  cmd.AddValue("enable_ml", "Enable ML-based mitigation", g_enable_ml);
  cmd.AddValue("enable_hybrid", "Enable Hybrid mitigation", g_enable_hybrid);
  cmd.AddValue("enable_rule", "Enable Rule-based mitigation", g_enable_rule);
  cmd.Parse(argc, argv);

  // Output files
  bsm_output.open("bsm_log.csv");
  bsm_output << "nodeId,posX,posY,velX,velY,timestamp" << "\n";

  attack_output.open("attack_log.csv");
  attack_output << "timestamp,attackerId,attackType,details" << "\n";

  mitigation_output.open("mitigation_log.csv");
  mitigation_output << "timestamp,nodeId,mitigationType,details" << "\n";

  trust_output.open("trust_log.csv");
  trust_output << "timestamp,nodeId,trustScore,lowTrustFlag" << "\n";

  ml_output.open("ml_detection_log.csv");
  ml_output << "timestamp,nodeId,eventType,suspiciousCount" << "\n";

  neighbor_output.open("neighbor_log.csv");
  neighbor_output << "timestamp,nodeId,neighborCount,minDistance" << "\n";

  jammer_output.open("jammer_log.csv");
  jammer_output << "timestamp,jammerId,eventType" << "\n";

  sybil_output.open("sybil_log.csv");
  sybil_output << "timestamp,fakeId,attackerId,posX,posY" << "\n";

  ddos_output.open("ddos_log.csv");
  ddos_output << "timestamp,attackerId,attackType,detail" << "\n";

  msg_falsification_output.open("msg_falsification_log.csv");
  msg_falsification_output << "timestamp,attackerId,fakePosX,fakePosY" << "\n";

  features_output.open("features_log.csv");
  features_output << "nodeId,posX,posY,speed,heading,timestamp,interArrivalTime,avgPayloadSize" << "\n";

  detection_output.open("detection_log.csv");
  detection_output << "timestamp,nodeId,attackType,detectionScore" << "\n";

  NodeContainer vehicles;
  vehicles.Create(g_numVehicles);

  // Load SUMO mobility (using the same file as before)
  std::string mobilityFile = "/home/jeanhuit/Documents/Workspace/simulation/roads-sumo/2025-12-05-21-50-47/mobility.tcl";
  Ns2MobilityHelper ns2(mobilityFile);
  ns2.Install(vehicles.Begin(), vehicles.End());

  // ----------------------------------------------------
  // WiFi 802.11p
  // ----------------------------------------------------
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  channel.AddPropagationLoss("ns3::FriisPropagationLossModel");

  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());
  phy.Set("TxPowerStart", DoubleValue(20));
  phy.Set("TxPowerEnd", DoubleValue(20));

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
  ip.SetBase("10.1.0.0", "255.255.0.0");  // Using same as original
  ip.Assign(devs);

  // Enhanced BSM apps + RSSI receiver
  for (uint32_t i = 0; i < vehicles.GetN(); i++)
  {
    Ptr<Node> node = vehicles.Get(i);

    // Create receiving socket
    Ptr<Socket> recvSock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    recvSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 5000));
    recvSock->SetRecvCallback(MakeCallback(&ReceivePacket));

    // Create sending socket
    Ptr<Socket> sendSock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    sendSock->SetAllowBroadcast(true);
    sendSock->Connect(InetSocketAddress(Ipv4Address("255.255.255.255"), 5000));

    // Determine if this node is an attacker and what type
    std::string attackType = "none";
    bool isAttacker = false;
    
    if (g_enable_ddos && i == 5) {
      attackType = "ddos";
      isAttacker = true;
    } else if (g_enable_sybil && i == 10) {
      attackType = "sybil";
      isAttacker = true;
    } else if (g_enable_replay && i == 15) {
      attackType = "replay";
      isAttacker = true;
    } else if (g_enable_msg_falsification && i == 20) {
      attackType = "falsification";
      isAttacker = true;
    }

    // Create enhanced BSM app
    Ptr<EnhancedBsmApp> app = CreateObject<EnhancedBsmApp>();
    app->Setup(sendSock, node, g_bsmInterval, attackType, isAttacker);
    node->AddApplication(app);
    app->SetStartTime(Seconds(1.0));
  }

  // Start attack injection (after simulation starts)
  if (g_enable_ddos) {
    Simulator::Schedule(Seconds(3.0), &InjectDdosAttack, vehicles, 5);
  }
  if (g_enable_sybil) {
    Simulator::Schedule(Seconds(4.0), &InjectSybilAttack, vehicles, 10);
  }
  if (g_enable_replay) {
    Simulator::Schedule(Seconds(6.0), &InjectReplayAttack, vehicles, 15);
  }
  if (g_enable_msg_falsification) {
    Simulator::Schedule(Seconds(8.0), &InjectMsgFalsification, vehicles, 20);
  }

  // Jammer node = node 25
  if (g_enable_jamming) {
    Ptr<Node> jnode = vehicles.Get(25);
    Ptr<Socket> jsock = Socket::CreateSocket(jnode, UdpSocketFactory::GetTypeId());
    jsock->SetAllowBroadcast(true);
    jsock->Connect(InetSocketAddress(Ipv4Address("255.255.255.255"), 5001));
    Simulator::Schedule(Seconds(2.0), &InjectJammerNode, jsock, 25);
  }

  // Start mitigation systems
  if (g_enable_trust) {
    Simulator::Schedule(Seconds(1.0), &UpdateTrustScores, vehicles);
  }
  if (g_enable_ml) {
    Simulator::Schedule(Seconds(1.0), &RunMLDetection, vehicles);
  }
  if (g_enable_rule) {
    Simulator::Schedule(Seconds(0.5), &UpdateRuleBasedDetection, vehicles);
  }
  if (g_enable_hybrid) {
    Simulator::Schedule(Seconds(1.5), &RunHybridDetection, vehicles);
  }

  // Start neighbor logging
  Simulator::Schedule(Seconds(1.0), &LogNeighbors, vehicles);

  Simulator::Stop(Seconds(g_simTime));
  Simulator::Run();
  Simulator::Destroy();

  // Close output files properly
  bsm_output.close();
  attack_output.close();
  mitigation_output.close();
  trust_output.close();
  ml_output.close();
  neighbor_output.close();
  jammer_output.close();
  sybil_output.close();
  ddos_output.close();
  msg_falsification_output.close();
  features_output.close();
  detection_output.close();

  return 0;
}