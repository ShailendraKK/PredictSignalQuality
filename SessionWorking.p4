/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_TCP = 6;
const bit<32> BASE = 0;
const bit<32> MAX = 10;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

#define REG_WIDTH 32
#define REG_ENTRIES 20
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t       tcp;
}
header intrinsic_metadata_t {
    bit<64> ingress_global_timestamp;
    bit<64> current_global_timestamp;
}


struct metadata {
    /* empty */
 intrinsic_metadata_t intrinsic_metadata;
 bit<32> packet_counter;
 bit<32> start_time;
 bit<32> end_time;
 bit<32> timestamp;
 bit<32> iat;
 bit<32> byte_counter;
 bit<32> hash_value;
 bit<32> index;
 bit<32> tmp;
 bit<32> start_iat_calc;
 bit<32> tx_bytes;
 bit<32> rx_bytes;
 bit<32> rx_packets;
 bit<32> tx_packets;
 bit<32> rx_timestamp;
 bit<32> tx_timestamp;
 bit<16> port_num;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start{
	transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }	
   }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
}


}



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    register<bit<REG_WIDTH>>(REG_ENTRIES) packet_reg;
    register<bit<REG_WIDTH>>(REG_ENTRIES) byte_reg;
    register<bit<REG_WIDTH>>(REG_ENTRIES) start_time;
    register<bit<REG_WIDTH>>(REG_ENTRIES) end_time;
    register<bit<REG_WIDTH>>(REG_ENTRIES) time_stamp;
    register<bit<REG_WIDTH>>(REG_ENTRIES) rx_timestamp;
    register<bit<16>>(REG_ENTRIES) mapping;
    register<bit<REG_WIDTH>>(REG_ENTRIES) iat;
    register<bit<REG_WIDTH>>(REG_ENTRIES) tmp;
    counter(10, CounterType.packets) c;
    action _update_hash(){
        hash(meta.hash_value,HashAlgorithm.crc16,BASE, { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },MAX);
    }
    action  _clear_packet_counter(bit<32> index){
           packet_reg.write(meta.hash_value + index,0);
    }
    action  _clear_byte_counter(bit<32> index){
           byte_reg.write(meta.hash_value + index,0);
    }

    action _update_byte_counter(bit<32> index){
        byte_reg.read(meta.byte_counter,meta.hash_value + index);
        meta.byte_counter = meta.byte_counter + (bit<REG_WIDTH>) hdr.ipv4.totalLen;
        byte_reg.write(meta.hash_value + index,meta.byte_counter);
    }

    action _update_packet_counter(bit<32> index){
           packet_reg.read(meta.packet_counter,meta.hash_value + index);
           meta.packet_counter = meta.packet_counter + 1;
           packet_reg.write(meta.hash_value + index,meta.packet_counter);
          
    }
    apply {
        meta.port_num = 770;
        if(hdr.ipv4.isValid())
        {
         if(standard_metadata.ingress_port == 768)
        {
            meta.index = 0;
        }
        else{
            meta.index = 10;
        }
        _update_hash();
        _update_packet_counter(meta.index);
        _update_byte_counter(meta.index);
        if(meta.packet_counter < 2){
             meta.start_time = meta.intrinsic_metadata.ingress_global_timestamp[31:0];
             start_time.write(meta.hash_value + meta.index,meta.start_time);
        }
        
        meta.end_time =   meta.intrinsic_metadata.ingress_global_timestamp[31:0];
        start_time.read(meta.start_time,meta.index + meta.hash_value);
        meta.timestamp = meta.end_time - meta.start_time;
        if(meta.timestamp > 50000000){
             c.count(0);
             byte_reg.read(meta.rx_bytes,meta.hash_value);
             byte_reg.read(meta.tx_bytes,meta.hash_value + 10);
             packet_reg.read(meta.rx_packets,meta.hash_value);
             packet_reg.read(meta.tx_packets,meta.hash_value + 10);
             start_time.read(meta.rx_timestamp,meta.index);
             start_time.read(meta.tx_timestamp,meta.hash_value  + 10);
             meta.rx_timestamp = meta.end_time - meta.rx_timestamp;
             meta.tx_timestamp = meta.end_time - meta.tx_timestamp;
             rx_timestamp.write(meta.hash_value + meta.index,meta.rx_timestamp);
             tmp.write(meta.hash_value + meta.index,1493649 * meta.rx_packets);
            if(meta.rx_bytes < 56498)
            {    c.count(1);
                  meta.port_num = 770;
             }
            else if(meta.rx_timestamp < (1493649 * meta.rx_packets)){
                 c.count(2);
                 meta.port_num = 771;
            }
            else if(meta.rx_bytes > 104901){
                 c.count(3);
                 meta.port_num = 771;
             }
             else if(meta.tx_timestamp < (1584880 * meta.tx_packets)){
                 c.count(4);
                 meta.port_num = 771;
            }
            else{  
                c.count(5);
                   meta.port_num = 770;
            }
             mapping.write(meta.hash_value + meta.index,meta.port_num);
             _clear_packet_counter(meta.index);
             _clear_byte_counter(meta.index);
        }
       
         
        }

        mapping.read(meta.port_num,meta.hash_value + meta.index);
        ipv4_forward(0102,meta.port_num);
      
        }
   }
            
     
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
