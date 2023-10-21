#include "network_interface.hh"

#include "arp_message.hh"
#include "ethernet_frame.hh"

using namespace std;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address )
  : ethernet_address_( ethernet_address ), ip_address_( ip_address )
{
  cerr << "DEBUG: Network interface has Ethernet address " << to_string( ethernet_address_ ) << " and IP address "
       << ip_address.ip() << "\n";
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram( const InternetDatagram& dgram, const Address& next_hop )
{
  const uint32_t next_ip = next_hop.ipv4_numeric();
  EthernetFrame frame;

  if ( arp_table_.count( next_ip ) ) {
    frame.header.src = ethernet_address_;
    frame.header.dst = arp_table_[next_ip];
    frame.payload = serialize( dgram );
    frame.header.type = EthernetHeader::TYPE_IPv4;

  } else if ( arp_clock_.count( next_ip ) == 0 ) {
    ARPMessage arp_msg;
    arp_msg.sender_ethernet_address = ethernet_address_;
    arp_msg.sender_ip_address = ip_address_.ipv4_numeric();
    arp_msg.target_ethernet_address = EthernetAddress { 0 };
    arp_msg.target_ip_address = next_ip;
    arp_msg.opcode = ARPMessage::OPCODE_REQUEST;

    frame.header.src = ethernet_address_;
    frame.header.dst = EthernetAddress { ETHERNET_BROADCAST };
    frame.payload = serialize( arp_msg );
    frame.header.type = EthernetHeader::TYPE_ARP;

    auto record = make_pair( next_hop, dgram );
    dgram_table_.push_back( record );
    arp_clock_[next_ip] = -1;

  } else if ( arp_clock_.count( next_ip ) && arp_clock_[next_ip] < 0 ) {
    auto record = make_pair( next_hop, dgram );
    dgram_table_.push_back( record );
    return;
  }

  outgoing_frames_.push( frame );
}

optional<InternetDatagram> NetworkInterface::recv_frame( const EthernetFrame& frame )
{
  EthernetHeader header = frame.header;

  // IPv4 packet
  if ( header.type == EthernetHeader::TYPE_IPv4 && header.dst == ethernet_address_ ) {
    InternetDatagram dgram;
    if ( parse( dgram, frame.payload ) ) {
      return dgram;
    }
  }

  // ARP message
  if ( header.type == EthernetHeader::TYPE_ARP ) {
    ARPMessage arp_msg;
    if ( parse( arp_msg, frame.payload ) ) {
      arp_table_[arp_msg.sender_ip_address] = arp_msg.sender_ethernet_address;
      arp_clock_[arp_msg.sender_ip_address] = 0;
    }

    // Reply to ARP message
    if ( arp_msg.target_ip_address == ip_address_.ipv4_numeric() && arp_msg.opcode == ARPMessage::OPCODE_REQUEST ) {
      arp_msg.target_ethernet_address = arp_msg.sender_ethernet_address;
      arp_msg.target_ip_address = arp_msg.sender_ip_address;
      arp_msg.sender_ethernet_address = ethernet_address_;
      arp_msg.sender_ip_address = ip_address_.ipv4_numeric();
      arp_msg.opcode = ARPMessage::OPCODE_REPLY;

      EthernetFrame return_frame;
      return_frame.header.src = ethernet_address_;
      return_frame.header.dst = arp_msg.target_ethernet_address;
      return_frame.payload = serialize( arp_msg );
      return_frame.header.type = EthernetHeader::TYPE_ARP;

      outgoing_frames_.push( return_frame );
    }
  }

  retrieve_datagram();
  return {};
}

optional<EthernetFrame> NetworkInterface::maybe_send()
{
  if ( outgoing_frames_.empty() ) {
    return {};
  }
  EthernetFrame frame = outgoing_frames_.front();
  outgoing_frames_.pop();
  return frame;
}

// ms_since_last_tick: the number of milliseconds since the last call to this method
void NetworkInterface::tick( const size_t ms_since_last_tick )
{
  if ( arp_clock_.empty() )
    return;
  for ( std::pair<uint32_t, int> entry : arp_clock_ ) {
    if ( arp_clock_[entry.first] >= 0 ) {
      arp_clock_[entry.first] += ms_since_last_tick;
      if ( arp_clock_[entry.first] >= 30000 ) {
        arp_table_.erase( entry.first );
        arp_clock_.erase( entry.first );
        break;
      }
    } else {
      arp_clock_[entry.first] -= ms_since_last_tick;
      if ( arp_clock_[entry.first] <= -5001 )
        arp_clock_.erase( entry.first );
      break;
    }
  }
  retrieve_datagram();
}

void NetworkInterface::retrieve_datagram()
{
  int idx = 0;
  for ( auto entry : dgram_table_ ) {
    if ( arp_clock_.count( entry.first.ipv4_numeric() ) && arp_clock_[entry.first.ipv4_numeric()] >= 0 ) {
      send_datagram( entry.second, entry.first );
      auto target = dgram_table_.begin();
      std::advance( target, idx );
      dgram_table_.erase( target );
      break;
    }
    idx++;
  }
}
