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
bit<32> pkt_26;
bit<32> pkt_27;
bit<32> pkt_28;
bit<32> pkt_29;
bit<32> pkt_30;
bit<32> pkt_31;
bit<32> pkt_32;
bit<32> pkt_33;
bit<32> pkt_34;
bit<32> pkt_35;
bit<32> pkt_36;
bit<32> pkt_37;
bit<32> pkt_38;
bit<32> pkt_39;
bit<32> pkt_40;
bit<32> pkt_41;
bit<32> pkt_42;
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

    action int_set_src() {
        hdr.pkts.pkt_0 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_0 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_1 : ternary;
            hdr.pkts.pkt_2 : ternary;
            hdr.pkts.pkt_3        : ternary;
            hdr.pkts.pkt_4        : ternary;
        }
        size = 256;
    }

    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_5 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_6 = tunnel_vni;
        hdr.pkts.pkt_5 = 1;
    }
    table ipv6_dest_vtep {
        actions = {

            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_7                    : exact;
            hdr.pkts.pkt_8                        : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }
    action acl_deny(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = acl_stats_index;
        hdr.pkts.pkt_12 = acl_meter_index;
        hdr.pkts.pkt_13 = acl_copy_reason;
        hdr.pkts.pkt_14 = nat_mode;
        hdr.pkts.pkt_15 = ingress_cos;
        hdr.pkts.pkt_16 = tc;
        hdr.pkts.pkt_17 = color;
    }
    action acl_permit(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_11 = acl_stats_index;
        hdr.pkts.pkt_12 = acl_meter_index;
        hdr.pkts.pkt_13 = acl_copy_reason;
        hdr.pkts.pkt_14 = nat_mode;
        hdr.pkts.pkt_15 = ingress_cos;
        hdr.pkts.pkt_16 = tc;
        hdr.pkts.pkt_17 = color;
    }
    action acl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = nexthop_index;
        hdr.pkts.pkt_20 = 0;
        hdr.pkts.pkt_11 = acl_stats_index;
        hdr.pkts.pkt_12 = acl_meter_index;
        hdr.pkts.pkt_13 = acl_copy_reason;
        hdr.pkts.pkt_14 = nat_mode;
        hdr.pkts.pkt_15 = ingress_cos;
        hdr.pkts.pkt_16 = tc;
        hdr.pkts.pkt_17 = color;
    }
    action acl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = ecmp_index;
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_11 = acl_stats_index;
        hdr.pkts.pkt_12 = acl_meter_index;
        hdr.pkts.pkt_13 = acl_copy_reason;
        hdr.pkts.pkt_14 = nat_mode;
        hdr.pkts.pkt_15 = ingress_cos;
        hdr.pkts.pkt_16 = tc;
        hdr.pkts.pkt_17 = color;
    }
    action acl_mirror(bit<32> session_id, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_21 = (bit<32>)session_id;
        hdr.pkts.pkt_11 = acl_stats_index;
        hdr.pkts.pkt_12 = acl_meter_index;
        hdr.pkts.pkt_14 = nat_mode;
        hdr.pkts.pkt_15 = ingress_cos;
        hdr.pkts.pkt_16 = tc;
        hdr.pkts.pkt_17 = color;
    }

    table ip_acl {
        actions = {

            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
            acl_mirror;
        }
        key = {
            hdr.pkts.pkt_22                 : ternary;
            hdr.pkts.pkt_23                 : ternary;
            hdr.pkts.pkt_2             : ternary;
            hdr.pkts.pkt_1             : ternary;
            hdr.pkts.pkt_24              : ternary;
            hdr.pkts.pkt_25 : exact;
            hdr.pkts.pkt_26 : exact;
            hdr.pkts.pkt_27                              : ternary;
            hdr.pkts.pkt_28                : ternary;
        }
        size = 512;
    }
    action ipv4_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_29 = 1;
        hdr.pkts.pkt_30 = urpf_bd_group;
        hdr.pkts.pkt_31 = hdr.pkts.pkt_32
    }
    table ipv4_urpf {
        actions = {
            ipv4_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_7          : exact;
            hdr.pkts.pkt_2 : exact;
        }
        size = 1024;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_29 = 1;
        hdr.pkts.pkt_30 = urpf_bd_group;
        hdr.pkts.pkt_31 = hdr.pkts.pkt_33
    }
    action urpf_miss() {
        hdr.pkts.pkt_34 = 1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_7          : exact;
            hdr.pkts.pkt_35 : lpm;
        }
        size = 512;
    }
    action multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_36 = mc_index;
        hdr.pkts.pkt_37 = 1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {

            multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_38      : exact;
            hdr.pkts.pkt_1 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_39 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_7          : exact;
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_24 : exact;
            hdr.pkts.pkt_40 : exact;
        }
        size = 1024;
    }
    action set_bd_flood_mc_index(bit<32> mc_index) {
        hdr.pkts.pkt_41 = mc_index;
    }
    table bd_flood {
        actions = {

            set_bd_flood_mc_index;
        }
        key = {
            hdr.pkts.pkt_38     : exact;
            hdr.pkts.pkt_42 : exact;
        }
        size = 1024;
    }
    apply {
        int_source.apply();
        ipv6_dest_vtep.apply();
        ip_acl.apply();
        ipv4_urpf.apply();
        ipv6_urpf_lpm.apply();
        ipv4_multicast_bridge_star_g.apply();
        nat_src.apply();
        bd_flood.apply();
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
