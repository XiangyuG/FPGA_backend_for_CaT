#include <core.p4>
#include <v1model.p4>
header packets_t {
bit<32> pkt_0;
bit<32> pkt_1;
bit<32> pkt_2;
bit<32> pkt_3;
bit<32> pkt_4;
bit<32> pkt_5;
bit<32> pkt_6;
bit<32> pkt_7;
bit<32> pkt_8;
bit<32> pkt_9;
bit<32> pkt_10;
bit<32> pkt_11;
bit<32> pkt_12;
bit<32> pkt_13;
bit<32> pkt_14;
bit<32> pkt_15;
bit<32> pkt_16;
bit<32> pkt_17;
bit<32> pkt_18;
bit<32> pkt_19;
bit<32> pkt_20;
bit<32> pkt_21;
bit<32> pkt_22;
bit<32> pkt_23;
bit<32> pkt_24;
bit<32> pkt_25;
}
struct headers {
    packets_t  pkts;
}

struct metadata {
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.pkts);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

        action set_ifindex(bit<32> ifindex, bit<32> port_type) {
               hdr.pkts.pkt_0 = ifindex;
               hdr.pkts.pkt_1 = port_type;
        }
        table ingress_port_mapping {
              actions = {
                  set_ifindex;
              }
              key = {
                  hdr.pkts.pkt_2 : exact;
              }
              size = 288;
        }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_0 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_3                    : exact;
            hdr.pkts.pkt_4                        : exact;
            hdr.pkts.pkt_5 : exact;
        }
        size = 1024;
    }
    action set_unicast() {
        hdr.pkts.pkt_6 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_6 = 2;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_6 = 2;
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_6 = 4;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = drop_reason;
    }
    table validate_packet {
        actions = {
            set_unicast;
            set_unicast_and_ipv6_src_is_link_local;
            set_multicast;
            set_multicast_and_ipv6_src_is_link_local;
            set_broadcast;
            set_malformed_packet;
        }
        key = {
            hdr.pkts.pkt_11            : ternary;
            hdr.pkts.pkt_12            : ternary;
            hdr.pkts.pkt_13           : ternary;
            hdr.pkts.pkt_14            : ternary;
            hdr.pkts.pkt_15        : ternary;
            hdr.pkts.pkt_16  : ternary;
            hdr.pkts.pkt_17  : ternary;
        }
        size = 512;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = nexthop_index;
        hdr.pkts.pkt_20 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = ecmp_index;
        hdr.pkts.pkt_20 = 1;
    }
    table ipv6_fib {
        actions = {
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_3          : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_22 = mc_index;
        hdr.pkts.pkt_23 = 1;
    }
    table ipv6_multicast_bridge {
        actions = {
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_24      : exact;
            hdr.pkts.pkt_25 : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }
    apply {
        ingress_port_mapping.apply();
        ipv4_src_vtep.apply();
        validate_packet.apply();
        ipv6_fib.apply();
        ipv6_multicast_bridge.apply();
    }
}

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {  }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
ingress(),
egress(),
MyComputeChecksum(),
MyDeparser()
) main;
