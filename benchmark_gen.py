import sys
import random

table_list = ["ingress_port_mapping", "ingress_port_properties", "validate_outer_ethernet", "validate_outer_ipv4_packet", "validate_outer_ipv6_packet",
        "validate_mpls_packet", "switch_config_params", "port_vlan_mapping", "spanning_tree", "ingress_qos_map_dscp", "ingress_qos_map_pcp",
        "ipsg", "ipsg_permit_special", "int_terminate", "int_sink_update_outer", "int_source", "sflow_ing_take_sample", "sflow_ingress",
        "adjust_lkp_fields", "outer_rmac", "tunnel", "tunnel_lookup_miss_0", "fabric_ingress_dst_lkp", "fabric_ingress_src_lkp", "native_packet_over_fabric",
        "ipv4_dest_vtep", "ipv4_src_vtep", "ipv6_dest_vtep", "ipv6_src_vtep", "mpls_0", "outer_ipv4_multicast", "outer_ipv4_multicast_star_g",
        "outer_ipv6_multicast", "outer_ipv6_multicast_star_g", "storm_control", "validate_packet", "ingress_l4_dst_port", "ingress_l4_src_port", "dmac", "smac", "mac_acl",
        "ip_acl", "ip_acl", "ipv4_racl", "ipv4_urpf", "ipv4_urpf_lpm", "ipv4_fib", "ipv4_fib_lpm", "ipv6_racl", "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib",
        "ipv6_fib_lpm", "urpf_bd", "ipv4_multicast_bridge", "ipv4_multicast_bridge_star_g", "ipv4_multicast_route", "ipv4_multicast_route_star_g",
        "ipv6_multicast_bridge", "ipv6_multicast_bridge_star_g", "ipv6_multicast_route", "ipv6_multicast_route_star_g", "nat_dst", "nat_flow",
        "nat_src", "nat_twice", "meter_index_0", "compute_ipv4_hashes", "compute_ipv6_hashes", "compute_non_ip_hashes", "compute_other_hashes",
        "meter_action", "ingress_bd_stats_0", "acl_stats_0", "fwd_result", "ecmp_group", "nexthop", "bd_flood", "lag_group", "learn_notify", "fabric_lag", "traffic_class",
        "drop_stats_0", "system_acl", "storm_control_stats_0"]
table_def = {}

ingress_port_mapping_content =  '''
        action set_ifindex(bit<16> ifindex, bit<2> port_type) {
               meta.ingress_metadata.ifindex = ifindex;
               meta.ingress_metadata.port_type = port_type;
        }
        table ingress_port_mapping {
              actions = {
                  set_ifindex;
              }
              key = {
                  standard_metadata.ingress_port: exact;
              }
              size = 288;
        }'''
table_def["ingress_port_mapping"] = ingress_port_mapping_content

ingress_port_properties_content = '''
        action set_ingress_port_properties(bit<16> if_label, bit<5> qos_group, bit<5> tc_qos_group, bit<8> tc, bit<2> color, bit<1> trust_dscp, bit<1> trust_pcp) {
               meta.acl_metadata.if_label = if_label;
               meta.qos_metadata.ingress_qos_group = qos_group;
               meta.qos_metadata.tc_qos_group = tc_qos_group;
               meta.qos_metadata.lkp_tc = tc;
               meta.meter_metadata.packet_color = color;
               meta.qos_metadata.trust_dscp = trust_dscp;
               meta.qos_metadata.trust_pcp = trust_pcp;
        }
        table ingress_port_properties {
              actions = {
                  set_ingress_port_properties;
              }
              key = {
                  standard_metadata.ingress_port: exact;
              }
              size = 288;
        }'''
table_def["ingress_port_properties"] = ingress_port_properties_content

validate_outer_ethernet_content = '''
    action malformed_outer_ethernet_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = 1w1;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    action set_valid_outer_unicast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }
    action set_valid_outer_unicast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_unicast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_unicast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_multicast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }
    action set_valid_outer_multicast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_multicast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_multicast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_broadcast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = 3w4;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }
    action set_valid_outer_broadcast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w4;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_broadcast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w4;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    action set_valid_outer_broadcast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = 3w4;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }
    table validate_outer_ethernet {
        actions = {
            malformed_outer_ethernet_packet;
            set_valid_outer_unicast_packet_untagged;
            set_valid_outer_unicast_packet_single_tagged;
            set_valid_outer_unicast_packet_double_tagged;
            set_valid_outer_unicast_packet_qinq_tagged;
            set_valid_outer_multicast_packet_untagged;
            set_valid_outer_multicast_packet_single_tagged;
            set_valid_outer_multicast_packet_double_tagged;
            set_valid_outer_multicast_packet_qinq_tagged;
            set_valid_outer_broadcast_packet_untagged;
            set_valid_outer_broadcast_packet_single_tagged;
            set_valid_outer_broadcast_packet_double_tagged;
            set_valid_outer_broadcast_packet_qinq_tagged;
        }
        key = {
            hdr.ethernet.srcAddr      : ternary;
            hdr.ethernet.dstAddr      : ternary;
            hdr.vlan_tag_[0].isValid(): exact;
            hdr.vlan_tag_[1].isValid(): exact;
        }
        size = 512;
    }'''
table_def["validate_outer_ethernet"] = validate_outer_ethernet_content

validate_outer_ipv4_packet_content = '''
    action set_valid_outer_ipv4_packet() {
        meta.l3_metadata.lkp_ip_type = 2w1;
        meta.l3_metadata.lkp_dscp = hdr.ipv4.diffserv;
        meta.l3_metadata.lkp_ip_version = hdr.ipv4.version;
    }
    action set_malformed_outer_ipv4_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = 1w1;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    table validate_outer_ipv4_packet {
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        key = {
            hdr.ipv4.version       : ternary;
            hdr.ipv4.ttl           : ternary;
            hdr.ipv4.srcAddr[31:24]: ternary;
        }
        size = 512;
    }'''

table_def["validate_outer_ipv4_packet"] = validate_outer_ipv4_packet_content

validate_outer_ipv6_packet_content = '''
    action set_valid_outer_ipv6_packet() {
        meta.l3_metadata.lkp_ip_type = 2w2;
        meta.l3_metadata.lkp_dscp = hdr.ipv6.trafficClass;
        meta.l3_metadata.lkp_ip_version = hdr.ipv6.version;
    }
    action set_malformed_outer_ipv6_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = 1w1;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    table validate_outer_ipv6_packet {
        actions = {
            set_valid_outer_ipv6_packet;
            set_malformed_outer_ipv6_packet;
        }
        key = {
            hdr.ipv6.version         : ternary;
            hdr.ipv6.hopLimit        : ternary;
            hdr.ipv6.srcAddr[127:112]: ternary;
        }
        size = 512;
    }'''
table_def["validate_outer_ipv6_packet"] = validate_outer_ipv6_packet_content

validate_mpls_packet_content = '''
    action set_valid_mpls_label1() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[0].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[0].exp;
    }
    action set_valid_mpls_label2() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[1].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[1].exp;
    }
    action set_valid_mpls_label3() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[2].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[2].exp;
    }
    table validate_mpls_packet {
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
        }
        key = {
            hdr.mpls[0].label    : ternary;
            hdr.mpls[0].bos      : ternary;
            hdr.mpls[0].isValid(): exact;
            hdr.mpls[1].label    : ternary;
            hdr.mpls[1].bos      : ternary;
            hdr.mpls[1].isValid(): exact;
            hdr.mpls[2].label    : ternary;
            hdr.mpls[2].bos      : ternary;
            hdr.mpls[2].isValid(): exact;
        }
        size = 512;
    }'''

table_def["validate_mpls_packet"] = validate_mpls_packet_content

switch_config_params_content = '''
    action deflect_on_drop(bit<1> enable_dod) {
        meta.intrinsic_metadata.deflect_on_drop = enable_dod;
    }
    action set_config_parameters(bit<1> enable_dod) {
        deflect_on_drop(enable_dod);
        meta.i2e_metadata.ingress_tstamp = (bit<32>)meta.intrinsic_metadata.ingress_global_timestamp;
        meta.ingress_metadata.ingress_port = standard_metadata.ingress_port;
        meta.l2_metadata.same_if_check = meta.ingress_metadata.ifindex;
        standard_metadata.egress_spec = 9w511;
        random(meta.ingress_metadata.sflow_take_sample, (bit<32>)0, (bit<32>)32w0x7fffffff);
    }
    table switch_config_params {
        actions = {
            set_config_parameters;
        }
        size = 1;
    }'''
table_def["switch_config_params"] = switch_config_params_content

port_vlan_mapping_content = '''
    action set_bd_properties(bit<16> bd, bit<16> vrf, bit<10> stp_group, bit<1> learning_enabled, bit<16> bd_label, bit<16> stats_idx, bit<10> rmac_group, bit<1> ipv4_unicast_enabled, bit<1> ipv6_unicast_enabled, bit<2> ipv4_urpf_mode, bit<2> ipv6_urpf_mode, bit<1> igmp_snooping_enabled, bit<1> mld_snooping_enabled, bit<1> ipv4_multicast_enabled, bit<1> ipv6_multicast_enabled, bit<16> mrpf_group, bit<16> ipv4_mcast_key, bit<1> ipv4_mcast_key_type, bit<16> ipv6_mcast_key, bit<1> ipv6_mcast_key_type) {
        meta.ingress_metadata.bd = bd;
        meta.ingress_metadata.outer_bd = bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.stp_group = stp_group;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l2_metadata.learning_enabled = learning_enabled;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_mcast_key_type = ipv4_mcast_key_type;
        meta.multicast_metadata.ipv4_mcast_key = ipv4_mcast_key;
        meta.multicast_metadata.ipv6_mcast_key_type = ipv6_mcast_key_type;
        meta.multicast_metadata.ipv6_mcast_key = ipv6_mcast_key;
    }
    action port_vlan_mapping_miss() {
        meta.l2_metadata.port_vlan_mapping_miss = 1w1;
    }
    table port_vlan_mapping {
        actions = {
            set_bd_properties;
            port_vlan_mapping_miss;
        }
        key = {
            meta.ingress_metadata.ifindex: exact;
            hdr.vlan_tag_[0].isValid()   : exact;
            hdr.vlan_tag_[0].vid         : exact;
            hdr.vlan_tag_[1].isValid()   : exact;
            hdr.vlan_tag_[1].vid         : exact;
        }
        size = 4096;
        @name(".bd_action_profile") implementation = action_profile(32w1024);
    }'''
table_def["port_vlan_mapping"] = port_vlan_mapping_content

spanning_tree_content = '''
    action set_stp_state(bit<3> stp_state) {
        meta.l2_metadata.stp_state = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            meta.ingress_metadata.ifindex: exact;
            meta.l2_metadata.stp_group   : exact;
        }
        size = 1024;
    }'''
table_def["spanning_tree"] = spanning_tree_content

ingress_qos_map_dscp_content = '''
    action nop() {
    }
    action set_ingress_tc(bit<8> tc) {
        meta.qos_metadata.lkp_tc = tc;
    }
    action set_ingress_color(bit<2> color) {
        meta.meter_metadata.packet_color = color;
    }
    action set_ingress_tc_and_color(bit<8> tc, bit<2> color) {
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table ingress_qos_map_dscp {
        actions = {
            nop;
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            meta.qos_metadata.ingress_qos_group: ternary;
            meta.l3_metadata.lkp_dscp          : ternary;
        }
        size = 64;
    }'''
table_def["ingress_qos_map_dscp"] = ingress_qos_map_dscp_content

ingress_qos_map_pcp_content = '''
    action nop() {
    }
    action set_ingress_tc(bit<8> tc) {
        meta.qos_metadata.lkp_tc = tc;
    }
    action set_ingress_color(bit<2> color) {
        meta.meter_metadata.packet_color = color;
    }
    action set_ingress_tc_and_color(bit<8> tc, bit<2> color) {
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table ingress_qos_map_pcp {
        actions = {
            nop;
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            meta.qos_metadata.ingress_qos_group: ternary;
            meta.l2_metadata.lkp_pcp           : ternary;
        }
        size = 64;
    }'''
table_def["ingress_qos_map_pcp"] = ingress_qos_map_pcp_content

ipsg_content = '''
    action on_miss() {
    }
    table ipsg {
        actions = {
            on_miss;
        }
        key = {
            meta.ingress_metadata.ifindex : exact;
            meta.ingress_metadata.bd      : exact;
            meta.l2_metadata.lkp_mac_sa   : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
        }
        size = 1024;
    }'''
table_def["ipsg"] = ipsg_content

ipsg_permit_special_content = '''
    action ipsg_miss() {
        meta.security_metadata.ipsg_check_fail = 1w1;
    }
    table ipsg_permit_special {
        actions = {
            ipsg_miss;
        }
        key = {
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.l3_metadata.lkp_l4_dport : ternary;
            meta.ipv4_metadata.lkp_ipv4_da: ternary;
        }
        size = 512;
    }'''
table_def["ipsg_permit_special"] = ipsg_permit_special_content

int_sink_update_outer_content = '''
    action int_sink_update_vxlan_gpe_v4() {
        hdr.vxlan_gpe.next_proto = hdr.vxlan_gpe_int_header.next_proto;
        hdr.vxlan_gpe_int_header.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - meta.int_metadata.insert_byte_cnt;
        hdr.udp.length_ = hdr.udp.length_ - meta.int_metadata.insert_byte_cnt;
    }
    action nop() {
    }
    table int_sink_update_outer {
        actions = {
            int_sink_update_vxlan_gpe_v4;
            nop;
        }
        key = {
            hdr.vxlan_gpe_int_header.isValid(): exact;
            hdr.ipv4.isValid()                : exact;
            meta.int_metadata_i2e.sink        : exact;
        }
        size = 2;
    }
'''
table_def["int_sink_update_outer"] = int_sink_update_outer_content

int_source_content = '''
    action int_set_src() {
        meta.int_metadata_i2e.source = 1w1;
    }
    action int_set_no_src() {
        meta.int_metadata_i2e.source = 1w0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.int_header.isValid()      : exact;
            hdr.ipv4.isValid()            : exact;
            meta.ipv4_metadata.lkp_ipv4_da: ternary;
            meta.ipv4_metadata.lkp_ipv4_sa: ternary;
            hdr.inner_ipv4.isValid()      : exact;
            hdr.inner_ipv4.dstAddr        : ternary;
            hdr.inner_ipv4.srcAddr        : ternary;
        }
        size = 256;
    }
'''
table_def["int_source"] = int_source_content

int_terminate_content = '''
    action int_sink(bit<32> mirror_id) {
        meta.int_metadata_i2e.sink = 1w1;
        meta.i2e_metadata.mirror_session_id = (bit<16>)mirror_id;
    }
    action int_sink_gpe(bit<32> mirror_id) {
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.gpe_int_hdr_len << 2;
        int_sink(mirror_id);
    }
    action int_no_sink() {
        meta.int_metadata_i2e.sink = 1w0;
    }
    table int_terminate {
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        key = {
            hdr.int_header.isValid()          : exact;
            hdr.vxlan_gpe_int_header.isValid(): exact;
            hdr.ipv4.isValid()                : exact;
            meta.ipv4_metadata.lkp_ipv4_da    : ternary;
            hdr.inner_ipv4.isValid()          : exact;
            hdr.inner_ipv4.dstAddr            : ternary;
        }
        size = 256;
    }
'''
table_def["int_terminate"] = int_terminate_content

sflow_ing_take_sample_content = '''
    action nop() {
    }
    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)sflow_i2e_mirror_id;
    }
    table sflow_ing_take_sample {
        actions = {
            nop;
            sflow_ing_pkt_to_cpu;
        }
        key = {
            meta.ingress_metadata.sflow_take_sample: ternary;
            meta.sflow_metadata.sflow_session_id   : exact;
        }
        size = 16;
    }'''
table_def["sflow_ing_take_sample"] = sflow_ing_take_sample_content

sflow_ingress_content = '''
    action sflow_ing_session_enable_0(bit<32> rate_thr, bit<16> session_id) {
        meta.ingress_metadata.sflow_take_sample = rate_thr + meta.ingress_metadata.sflow_take_sample;
        meta.sflow_metadata.sflow_session_id = session_id;
    }
    table sflow_ingress {
        actions = {
            sflow_ing_session_enable_0;
        }
        key = {
            meta.ingress_metadata.ifindex : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa: ternary;
            meta.ipv4_metadata.lkp_ipv4_da: ternary;
            hdr.sflow.isValid()           : exact;
        }
        size = 512;
    }'''
table_def["sflow_ingress"] = sflow_ingress_content


adjust_lkp_fields_content = '''
    action non_ip_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }
    action ipv4_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv4.ttl;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    action ipv6_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv6.hopLimit;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    table adjust_lkp_fields {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.ipv4.isValid(): exact;
            hdr.ipv6.isValid(): exact;
        }
    }'''
table_def["adjust_lkp_fields"] = adjust_lkp_fields_content

outer_rmac_content = '''
    action on_miss() {
    }
    action outer_rmac_hit() {
        meta.l3_metadata.rmac_hit = 1w1;
    }
    table outer_rmac {
        actions = {
            on_miss;
            outer_rmac_hit;
        }
        key = {
            meta.l3_metadata.rmac_group: exact;
            hdr.ethernet.dstAddr       : exact;
        }
        size = 1024;
    }'''

table_def["outer_rmac"] = outer_rmac_content

tunnel_content = '''
    action nop() {
    }
    action tunnel_lookup_miss() {
    }
    action terminate_tunnel_inner_non_ip(bit<16> bd, bit<16> bd_label, bit<16> stats_idx) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.ingress_metadata.bd = bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l3_metadata.lkp_ip_type = 2w0;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }
    action terminate_tunnel_inner_ethernet_ipv4(bit<16> bd, bit<16> vrf, bit<10> rmac_group, bit<16> bd_label, bit<1> ipv4_unicast_enabled, bit<2> ipv4_urpf_mode, bit<1> igmp_snooping_enabled, bit<16> stats_idx, bit<1> ipv4_multicast_enabled, bit<16> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l3_metadata.lkp_ip_type = 2w1;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
    }
    action terminate_tunnel_inner_ipv4(bit<16> vrf, bit<10> rmac_group, bit<2> ipv4_urpf_mode, bit<1> ipv4_unicast_enabled, bit<1> ipv4_multicast_enabled, bit<16> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = 2w1;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
    }
    action terminate_tunnel_inner_ethernet_ipv6(bit<16> bd, bit<16> vrf, bit<10> rmac_group, bit<16> bd_label, bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode, bit<1> mld_snooping_enabled, bit<16> stats_idx, bit<1> ipv6_multicast_enabled, bit<16> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l3_metadata.lkp_ip_type = 2w2;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
    }
    action terminate_tunnel_inner_ipv6(bit<16> vrf, bit<10> rmac_group, bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode, bit<1> ipv6_multicast_enabled, bit<16> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = 2w2;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
    }
    table tunnel {
        actions = {
            nop;
            tunnel_lookup_miss;
            terminate_tunnel_inner_non_ip;
            terminate_tunnel_inner_ethernet_ipv4;
            terminate_tunnel_inner_ipv4;
            terminate_tunnel_inner_ethernet_ipv6;
            terminate_tunnel_inner_ipv6;
        }
        key = {
            meta.tunnel_metadata.tunnel_vni         : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
            hdr.inner_ipv4.isValid()                : exact;
            hdr.inner_ipv6.isValid()                : exact;
        }
        size = 1024;
    }'''

table_def["tunnel"] = tunnel_content

tunnel_lookup_miss_0_content = '''
    action non_ip_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }
    action ipv4_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv4.ttl;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    action ipv6_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv6.hopLimit;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.ipv4.isValid(): exact;
            hdr.ipv6.isValid(): exact;
        }
    }'''

table_def["tunnel_lookup_miss_0"] = tunnel_lookup_miss_0_content

fabric_ingress_dst_lkp_content = '''
    action nop() {
    }
    action terminate_cpu_packet() {
        standard_metadata.egress_spec = (bit<9>)hdr.fabric_header.dstPortOrGroup;
        meta.egress_metadata.bypass = hdr.fabric_header_cpu.txBypass;
        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header_cpu.mcast_grp;
        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_cpu.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }
    action switch_fabric_unicast_packet() {
        meta.fabric_metadata.fabric_header_present = 1w1;
        meta.fabric_metadata.dst_device = hdr.fabric_header.dstDevice;
        meta.fabric_metadata.dst_port = hdr.fabric_header.dstPortOrGroup;
    }
    action terminate_fabric_unicast_packet() {
        standard_metadata.egress_spec = (bit<9>)hdr.fabric_header.dstPortOrGroup;
        meta.tunnel_metadata.tunnel_terminate = hdr.fabric_header_unicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = hdr.fabric_header_unicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = hdr.fabric_header_unicast.nexthopIndex;
        meta.l3_metadata.routed = hdr.fabric_header_unicast.routed;
        meta.l3_metadata.outer_routed = hdr.fabric_header_unicast.outerRouted;
        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_unicast.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }
    action switch_fabric_multicast_packet() {
        meta.fabric_metadata.fabric_header_present = 1w1;
        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header.dstPortOrGroup;
    }
    action terminate_fabric_multicast_packet() {
        meta.tunnel_metadata.tunnel_terminate = hdr.fabric_header_multicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = hdr.fabric_header_multicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = 16w0;
        meta.l3_metadata.routed = hdr.fabric_header_multicast.routed;
        meta.l3_metadata.outer_routed = hdr.fabric_header_multicast.outerRouted;
        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header_multicast.mcastGrp;
        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_multicast.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }
    table fabric_ingress_dst_lkp {
        actions = {
            nop;
            terminate_cpu_packet;
            switch_fabric_unicast_packet;
            terminate_fabric_unicast_packet;
            switch_fabric_multicast_packet;
            terminate_fabric_multicast_packet;
        }
        key = {
            hdr.fabric_header.dstDevice: exact;
        }
    }'''
table_def["fabric_ingress_dst_lkp"] = fabric_ingress_dst_lkp_content

fabric_ingress_src_lkp_content = '''
    action nop() {
    }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            nop;
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.fabric_header_multicast.ingressIfindex: exact;
        }
        size = 1024;
    }'''
table_def["fabric_ingress_src_lkp"] = fabric_ingress_src_lkp_content

native_packet_over_fabric_content = '''
    action non_ip_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }
    action ipv4_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    action ipv6_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv6.nextHdr;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }
    table native_packet_over_fabric {
        actions = {
            non_ip_over_fabric;
            ipv4_over_fabric;
            ipv6_over_fabric;
        }
        key = {
            hdr.ipv4.isValid(): exact;
            hdr.ipv6.isValid(): exact;
        }
        size = 1024;
    }'''
table_def["native_packet_over_fabric"] = native_packet_over_fabric_content

ipv4_dest_vtep_content = '''
    action nop() {
    }
    action set_tunnel_termination_flag() {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
    }
    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni) {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
    }
    table ipv4_dest_vtep {
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            meta.l3_metadata.vrf                    : exact;
            hdr.ipv4.dstAddr                        : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
        }
        size = 1024;
    }'''

table_def["ipv4_dest_vtep"] = ipv4_dest_vtep_content

ipv4_src_vtep_content = '''
    action on_miss() {
    }
    action src_vtep_hit(bit<16> ifindex) {
        meta.ingress_metadata.ifindex = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            on_miss;
            src_vtep_hit;
        }
        key = {
            meta.l3_metadata.vrf                    : exact;
            hdr.ipv4.srcAddr                        : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
        }
        size = 1024;
    }'''
table_def["ipv4_src_vtep"] = ipv4_src_vtep_content

ipv6_dest_vtep_content = '''
    action nop() {
    }
    action set_tunnel_termination_flag() {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
    }
    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni) {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
    }
    table ipv6_dest_vtep {
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            meta.l3_metadata.vrf                    : exact;
            hdr.ipv6.dstAddr                        : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_dest_vtep"] = ipv6_dest_vtep_content

ipv6_src_vtep_content = '''
    action on_miss() {
    }
    action src_vtep_hit(bit<16> ifindex) {
        meta.ingress_metadata.ifindex = ifindex;
    }
    table ipv6_src_vtep {
        actions = {
            on_miss;
            src_vtep_hit;
        }
        key = {
            meta.l3_metadata.vrf                    : exact;
            hdr.ipv6.srcAddr                        : exact;
            meta.tunnel_metadata.ingress_tunnel_type: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_src_vtep"] = ipv6_src_vtep_content

mpls_0_content = '''
    action terminate_eompls(bit<16> bd, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }
    action terminate_vpls(bit<16> bd, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }
    action terminate_ipv4_over_mpls(bit<16> vrf, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = 2w1;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
    }
    action terminate_ipv6_over_mpls(bit<16> vrf, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = 2w2;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;
    }
    action terminate_pw(bit<16> ifindex) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }
    action forward_mpls(bit<16> nexthop_index) {
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = 2w0;
        meta.l3_metadata.fib_hit = 1w1;
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }
    table mpls_0 {
        actions = {
            terminate_eompls;
            terminate_vpls;
            terminate_ipv4_over_mpls;
            terminate_ipv6_over_mpls;
            terminate_pw;
            forward_mpls;
        }
        key = {
            meta.tunnel_metadata.mpls_label: exact;
            hdr.inner_ipv4.isValid()       : exact;
            hdr.inner_ipv6.isValid()       : exact;
        }
        size = 1024;
    }'''
table_def["mpls_0"] = mpls_0_content

outer_ipv4_multicast_content = '''
    action nop() {
    }
    action on_miss() {
    }
    action outer_multicast_route_s_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_bridge_s_g_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table outer_ipv4_multicast {
        actions = {
            nop;
            on_miss;
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            meta.multicast_metadata.ipv4_mcast_key_type: exact;
            meta.multicast_metadata.ipv4_mcast_key     : exact;
            hdr.ipv4.srcAddr                           : exact;
            hdr.ipv4.dstAddr                           : exact;
        }
        size = 1024;
    }'''
table_def["outer_ipv4_multicast"] = outer_ipv4_multicast_content

outer_ipv4_multicast_star_g_content = '''
    action nop() {
    }
    action outer_multicast_route_sm_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.multicast_metadata.outer_mcast_mode = 2w1;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.multicast_metadata.outer_mcast_mode = 2w2;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_bridge_star_g_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table outer_ipv4_multicast_star_g {
        actions = {
            nop;
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            meta.multicast_metadata.ipv4_mcast_key_type: exact;
            meta.multicast_metadata.ipv4_mcast_key     : exact;
            hdr.ipv4.dstAddr                           : ternary;
        }
        size = 512;
    }'''
table_def["outer_ipv4_multicast_star_g"] = outer_ipv4_multicast_star_g_content

outer_ipv6_multicast_content = '''
    action nop() {
    }
    action on_miss() {
    }
    action outer_multicast_route_s_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_bridge_s_g_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table outer_ipv6_multicast {
        actions = {
            nop;
            on_miss;
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            meta.multicast_metadata.ipv6_mcast_key_type: exact;
            meta.multicast_metadata.ipv6_mcast_key     : exact;
            hdr.ipv6.srcAddr                           : exact;
            hdr.ipv6.dstAddr                           : exact;
        }
        size = 1024;
    }'''
table_def["outer_ipv6_multicast"] = outer_ipv6_multicast_content

outer_ipv6_multicast_star_g_content = '''
    action nop() {
    }
    action outer_multicast_route_sm_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.multicast_metadata.outer_mcast_mode = 2w1;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<16> mc_index, bit<16> mcast_rpf_group) {
        meta.multicast_metadata.outer_mcast_mode = 2w2;
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.multicast_metadata.outer_mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | meta.multicast_metadata.bd_mrpf_group;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action outer_multicast_bridge_star_g_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.tunnel_metadata.tunnel_terminate = 1w1;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            nop;
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            meta.multicast_metadata.ipv6_mcast_key_type: exact;
            meta.multicast_metadata.ipv6_mcast_key     : exact;
            hdr.ipv6.dstAddr                           : ternary;
        }
        size = 512;
    }'''
table_def["outer_ipv6_multicast_star_g"] = outer_ipv6_multicast_star_g_content


storm_control_content = '''
    action nop() {
    }
    action set_storm_control_meter(bit<32> meter_idx) {
        storm_control_meter.execute_meter((bit<32>)meter_idx, meta.meter_metadata.packet_color);
        meta.meter_metadata.meter_index = (bit<16>)meter_idx;
    }
    table storm_control {
        actions = {
            nop;
            set_storm_control_meter;
        }
        key = {
            standard_metadata.ingress_port: exact;
            meta.l2_metadata.lkp_pkt_type : ternary;
        }
        size = 512;
    }'''
table_def["storm_control"] = storm_control_content

validate_packet_content = '''
    action nop() {
    }
    action set_unicast() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        meta.l2_metadata.lkp_pkt_type = 3w1;
        meta.ipv6_metadata.ipv6_src_is_link_local = 1w1;
    }
    action set_multicast() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        meta.l2_metadata.lkp_pkt_type = 3w2;
        meta.ipv6_metadata.ipv6_src_is_link_local = 1w1;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w1;
    }
    action set_broadcast() {
        meta.l2_metadata.lkp_pkt_type = 3w4;
        meta.l2_metadata.bd_stats_idx = meta.l2_metadata.bd_stats_idx + 16w2;
    }
    action set_malformed_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = 1w1;
        meta.ingress_metadata.drop_reason = drop_reason;
    }
    table validate_packet {
        actions = {
            nop;
            set_unicast;
            set_unicast_and_ipv6_src_is_link_local;
            set_multicast;
            set_multicast_and_ipv6_src_is_link_local;
            set_broadcast;
            set_malformed_packet;
        }
        key = {
            meta.l2_metadata.lkp_mac_sa            : ternary;
            meta.l2_metadata.lkp_mac_da            : ternary;
            meta.l3_metadata.lkp_ip_type           : ternary;
            meta.l3_metadata.lkp_ip_ttl            : ternary;
            meta.l3_metadata.lkp_ip_version        : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa[31:24]  : ternary;
            meta.ipv6_metadata.lkp_ipv6_sa[127:112]: ternary;
        }
        size = 512;
    }'''
table_def["validate_packet"] = validate_packet_content

ingress_l4_dst_port_content = '''
    action nop() {
    }
    action set_ingress_dst_port_range_id(bit<8> range_id) {
        meta.acl_metadata.ingress_dst_port_range_id = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            nop;
            set_ingress_dst_port_range_id;
        }
        key = {
            meta.l3_metadata.lkp_l4_dport: range;
        }
        size = 512;
    }'''
table_def["ingress_l4_dst_port"] = ingress_l4_dst_port_content

ingress_l4_src_port_content = '''
    action nop() {
    }
    action set_ingress_src_port_range_id(bit<8> range_id) {
        meta.acl_metadata.ingress_src_port_range_id = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            nop;
            set_ingress_src_port_range_id;
        }
        key = {
            meta.l3_metadata.lkp_l4_sport: range;
        }
        size = 512;
    }'''
table_def["ingress_l4_src_port"] = ingress_l4_src_port_content

dmac_content = '''
    action nop() {
    }
    action dmac_hit(bit<16> ifindex) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
    }
    action dmac_multicast_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action dmac_miss() {
        meta.ingress_metadata.egress_ifindex = 16w65535;
        meta.fabric_metadata.dst_device = 8w127;
    }
    action dmac_redirect_nexthop(bit<16> nexthop_index) {
        meta.l2_metadata.l2_redirect = 1w1;
        meta.l2_metadata.l2_nexthop = nexthop_index;
        meta.l2_metadata.l2_nexthop_type = 2w0;
    }
    action dmac_redirect_ecmp(bit<16> ecmp_index) {
        meta.l2_metadata.l2_redirect = 1w1;
        meta.l2_metadata.l2_nexthop = ecmp_index;
        meta.l2_metadata.l2_nexthop_type = 2w1;
    }
    action dmac_drop() {
        mark_to_drop();
    }
    table dmac {
        support_timeout = true;
        actions = {
            nop;
            dmac_hit;
            dmac_multicast_hit;
            dmac_miss;
            dmac_redirect_nexthop;
            dmac_redirect_ecmp;
            dmac_drop;
        }
        key = {
            meta.ingress_metadata.bd   : exact;
            meta.l2_metadata.lkp_mac_da: exact;
        }
        size = 1024;
    }'''
table_def["dmac"] = dmac_content

smac_content = '''
    action nop() {
    }
    action smac_miss() {
        meta.l2_metadata.l2_src_miss = 1w1;
    }
    action smac_hit(bit<16> ifindex) {
        meta.l2_metadata.l2_src_move = meta.ingress_metadata.ifindex ^ ifindex;
    }
    table smac {
        actions = {
            nop;
            smac_miss;
            smac_hit;
        }
        key = {
            meta.ingress_metadata.bd   : exact;
            meta.l2_metadata.lkp_mac_sa: exact;
        }
        size = 1024;
    }'''
table_def["smac"] = smac_content

mac_acl_content = '''
    action nop() {
    }
    action acl_deny(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_deny = 1w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_permit(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = nexthop_index;
        meta.acl_metadata.acl_nexthop_type = 2w0;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = ecmp_index;
        meta.acl_metadata.acl_nexthop_type = 2w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_mirror(bit<32> session_id, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;
        clone3(CloneType.I2E, (bit<32>)session_id, { meta.i2e_metadata.ingress_tstamp, meta.i2e_metadata.mirror_session_id });
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table mac_acl {
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
            acl_mirror;
        }
        key = {
            meta.acl_metadata.if_label   : ternary;
            meta.acl_metadata.bd_label   : ternary;
            meta.l2_metadata.lkp_mac_sa  : ternary;
            meta.l2_metadata.lkp_mac_da  : ternary;
            meta.l2_metadata.lkp_mac_type: ternary;
        }
        size = 512;
    }'''
table_def["mac_acl"] = mac_acl_content

ip_acl_content = '''
    action nop() {
    }
    action acl_deny(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_deny = 1w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_permit(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = nexthop_index;
        meta.acl_metadata.acl_nexthop_type = 2w0;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = ecmp_index;
        meta.acl_metadata.acl_nexthop_type = 2w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_mirror(bit<32> session_id, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;
        clone3(CloneType.I2E, (bit<32>)session_id, { meta.i2e_metadata.ingress_tstamp, meta.i2e_metadata.mirror_session_id });
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table ip_acl {
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
            acl_mirror;
        }
        key = {
            meta.acl_metadata.if_label                 : ternary;
            meta.acl_metadata.bd_label                 : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa             : ternary;
            meta.ipv4_metadata.lkp_ipv4_da             : ternary;
            meta.l3_metadata.lkp_ip_proto              : ternary;
            meta.acl_metadata.ingress_src_port_range_id: exact;
            meta.acl_metadata.ingress_dst_port_range_id: exact;
            hdr.tcp.flags                              : ternary;
            meta.l3_metadata.lkp_ip_ttl                : ternary;
        }
        size = 512;
    }'''
table_def["ip_acl"] = ip_acl_content

ipv6_acl_content = '''
    action nop() {
    }
    action acl_deny(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_deny = 1w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_permit(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = nexthop_index;
        meta.acl_metadata.acl_nexthop_type = 2w0;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = 1w1;
        meta.acl_metadata.acl_nexthop = ecmp_index;
        meta.acl_metadata.acl_nexthop_type = 2w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action acl_mirror(bit<32> session_id, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;
        clone3(CloneType.I2E, (bit<32>)session_id, { meta.i2e_metadata.ingress_tstamp, meta.i2e_metadata.mirror_session_id });
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }

    table ip_acl {
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
            acl_mirror;
        }
        key = {
            meta.acl_metadata.if_label                 : ternary;
            meta.acl_metadata.bd_label                 : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa             : ternary;
            meta.ipv4_metadata.lkp_ipv4_da             : ternary;
            meta.l3_metadata.lkp_ip_proto              : ternary;
            meta.acl_metadata.ingress_src_port_range_id: exact;
            meta.acl_metadata.ingress_dst_port_range_id: exact;
            hdr.tcp.flags                              : ternary;
            meta.l3_metadata.lkp_ip_ttl                : ternary;
        }
        size = 512;
    }'''

table_def["ip_acl"] = ipv6_acl_content

ipv4_racl_content = '''
    action nop() {
    }
    action racl_deny(bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_deny = 1w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_permit(bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = 1w1;
        meta.acl_metadata.racl_nexthop = nexthop_index;
        meta.acl_metadata.racl_nexthop_type = 2w0;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = 1w1;
        meta.acl_metadata.racl_nexthop = ecmp_index;
        meta.acl_metadata.racl_nexthop_type = 2w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table ipv4_racl {
        actions = {
            nop;
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            meta.acl_metadata.bd_label                 : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa             : ternary;
            meta.ipv4_metadata.lkp_ipv4_da             : ternary;
            meta.l3_metadata.lkp_ip_proto              : ternary;
            meta.acl_metadata.ingress_src_port_range_id: exact;
            meta.acl_metadata.ingress_dst_port_range_id: exact;
        }
        size = 512;
    }'''
table_def["ipv4_racl"] = ipv4_racl_content

ipv4_urpf_content = '''
    action on_miss() {
    }
    action ipv4_urpf_hit(bit<16> urpf_bd_group) {
        meta.l3_metadata.urpf_hit = 1w1;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = meta.ipv4_metadata.ipv4_urpf_mode;
    }
    table ipv4_urpf {
        actions = {
            on_miss;
            ipv4_urpf_hit;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
        }
        size = 1024;
    }'''
table_def["ipv4_urpf"] = ipv4_urpf_content

ipv4_urpf_lpm_content = '''
    action ipv4_urpf_hit(bit<16> urpf_bd_group) {
        meta.l3_metadata.urpf_hit = 1w1;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = meta.ipv4_metadata.ipv4_urpf_mode;
    }
    action urpf_miss() {
        meta.l3_metadata.urpf_check_fail = 1w1;
    }
    table ipv4_urpf_lpm {
        actions = {
            ipv4_urpf_hit;
            urpf_miss;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: lpm;
        }
        size = 512;
    }'''
table_def["ipv4_urpf_lpm"] = ipv4_urpf_lpm_content

ipv4_fib_content = '''
    action on_miss() {
    }
    action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = 2w0;
    }
    action fib_hit_ecmp(bit<16> ecmp_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = ecmp_index;
        meta.l3_metadata.fib_next
    table ipv4_fib {
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv4_fib"] = ipv4_fib_content


ipv4_fib_lpm_content = '''
    action on_miss() {
    }
    action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = 2w0;
    }
    action fib_hit_ecmp(bit<16> ecmp_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = ecmp_index;
        meta.l3_metadata.fib_nexthop_type = 2w1;
    }
    table ipv4_fib_lpm {
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: lpm;
        }
        size = 512;
    }'''
table_def["ipv4_fib_lpm"] = ipv4_fib_lpm_content

ipv6_racl_content = '''
    action nop() {
    }
    action racl_deny(bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_deny = 1w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_permit(bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = 1w1;
        meta.acl_metadata.racl_nexthop = nexthop_index;
        meta.acl_metadata.racl_nexthop_type = 2w0;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    action racl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_copy_reason, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = 1w1;
        meta.acl_metadata.racl_nexthop = ecmp_index;
        meta.acl_metadata.racl_nexthop_type = 2w1;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }
    table ipv6_racl {
        actions = {
            nop;
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            meta.acl_metadata.bd_label                 : ternary;
            meta.ipv6_metadata.lkp_ipv6_sa             : ternary;
            meta.ipv6_metadata.lkp_ipv6_da             : ternary;
            meta.l3_metadata.lkp_ip_proto              : ternary;
            meta.acl_metadata.ingress_src_port_range_id: exact;
            meta.acl_metadata.ingress_dst_port_range_id: exact;
        }
        size = 512;
    }'''
table_def["ipv6_racl"] = ipv6_racl_content

ipv6_urpf_content = '''
    action on_miss() {
    }
    action ipv6_urpf_hit(bit<16> urpf_bd_group) {
        meta.l3_metadata.urpf_hit = 1w1;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = meta.ipv6_metadata.ipv6_urpf_mode;
    }
    table ipv6_urpf {
        actions = {
            on_miss;
            ipv6_urpf_hit;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_urpf"] = ipv6_urpf_content

ipv6_urpf_lpm_content = '''
    action ipv6_urpf_hit(bit<16> urpf_bd_group) {
        meta.l3_metadata.urpf_hit = 1w1;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = meta.ipv6_metadata.ipv6_urpf_mode;
    }
    action urpf_miss() {
        meta.l3_metadata.urpf_check_fail = 1w1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: lpm;
        }
        size = 512;
    }'''
table_def["ipv6_urpf_lpm"] = ipv6_urpf_lpm_content

ipv6_fib_content = '''
    action on_miss() {
    }
    @name(".fib_hit_nexthop") action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = 2w0;
    }
    @name(".fib_hit_ecmp") action fib_hit_ecmp(bit<16> ecmp_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = ecmp_index;
        meta.l3_metadata.fib_nexthop_type = 2w1;
    }
    @name(".ipv6_fib") table ipv6_fib {
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_fib"] = ipv6_fib_content

ipv6_fib_lpm_content = '''
    action on_miss() {
    }
    action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = 2w0;
    }
    action fib_hit_ecmp(bit<16> ecmp_index) {
        meta.l3_metadata.fib_hit = 1w1;
        meta.l3_metadata.fib_nexthop = ecmp_index;
        meta.l3_metadata.fib_nexthop_type = 2w1;
    }
    table ipv6_fib_lpm {
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_da: lpm;
        }
        size = 512;
    }'''
table_def["ipv6_fib_lpm"] = ipv6_fib_lpm_content

urpf_bd_content = '''
    action nop() {
    }
    action urpf_bd_miss() {
        meta.l3_metadata.urpf_check_fail = 1w1;
    }
    table urpf_bd {
        actions = {
            nop;
            urpf_bd_miss;
        }
        key = {
            meta.l3_metadata.urpf_bd_group: exact;
            meta.ingress_metadata.bd      : exact;
        }
        size = 1024;
    }'''
table_def["urpf_bd"] = urpf_bd_content

ipv4_multicast_bridge_content = '''
    action on_miss() {
    }
    action multicast_bridge_s_g_hit(bit<16> mc_index) {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = 1w1;
    }
    table ipv4_multicast_bridge {
        actions = {
            on_miss;
            multicast_bridge_s_g_hit;
        }
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv4_multicast_bridge"] = ipv4_multicast_bridge_content

ipv4_multicast_bridge_star_g_content = '''
    action nop() {
    }
    action multicast_bridge_star_g_hit(bit<16> mc_index) {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = 1w1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {
            nop;
            multicast_bridge_star_g_hit;
        }
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv4_multicast_bridge_star_g"] = ipv4_multicast_bridge_star_g_content

ipv4_multicast_route_content = '''
    action on_miss_0() {
        ipv4_multicast_route_s_g_stats.count();
    }
    action multicast_route_s_g_hit_0(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv4_multicast_route_s_g_stats.count();
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_mode = 2w1;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv4_multicast_route {
        actions = {
            on_miss_0;
            multicast_route_s_g_hit_0;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        size = 1024;
        @name(".ipv4_multicast_route_s_g_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["ipv4_multicast_route"] = ipv4_multicast_route_content

ipv4_multicast_route_star_g_content = '''
    action multicast_route_star_g_miss_0() {
        ipv4_multicast_route_star_g_stats.count();
        meta.l3_metadata.l3_copy = 1w1;
    }
    action multicast_route_sm_star_g_hit_0(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv4_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = 2w1;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
    }
    action multicast_route_bidir_star_g_hit_0(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv4_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = 2w2;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv4_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_0;
            multicast_route_sm_star_g_hit_0;
            multicast_route_bidir_star_g_hit_0;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
        }
        size = 1024;
        @name(".ipv4_multicast_route_star_g_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["ipv4_multicast_route_star_g"] = ipv4_multicast_route_star_g_content

ipv6_multicast_bridge_content = '''
    action on_miss() {
    }
    action multicast_bridge_s_g_hit(bit<16> mc_index) {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = 1w1;
    }
    table ipv6_multicast_bridge {
        actions = {
            on_miss;
            multicast_bridge_s_g_hit;
        }
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_multicast_bridge"] = ipv6_multicast_bridge_content

ipv6_multicast_bridge_star_g_content = '''
    action nop() {
    }
    action multicast_bridge_star_g_hit(bit<16> mc_index) {
        meta.multicast_metadata.multicast_bridge_mc_index = mc_index;
        meta.multicast_metadata.mcast_bridge_hit = 1w1;
    }
    table ipv6_multicast_bridge_star_g {
        actions = {
            nop;
            multicast_bridge_star_g_hit;
        }
        key = {
            meta.ingress_metadata.bd      : exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        size = 1024;
    }'''
table_def["ipv6_multicast_bridge_star_g"] = ipv6_multicast_bridge_star_g_content

ipv6_multicast_route_content = '''
    action on_miss_1() {
        ipv6_multicast_route_s_g_stats.count();
    }
    action multicast_route_s_g_hit_1(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv6_multicast_route_s_g_stats.count();
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_mode = 2w1;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv6_multicast_route {
        actions = {
            on_miss_1;
            multicast_route_s_g_hit_1;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_sa: exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        size = 1024;
        @name(".ipv6_multicast_route_s_g_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["ipv6_multicast_route"] = ipv6_multicast_route_content

ipv6_multicast_route_star_g_content = '''
    action multicast_route_star_g_miss_1() {
        ipv6_multicast_route_star_g_stats.count();
        meta.l3_metadata.l3_copy = 1w1;
    }
    action multicast_route_sm_star_g_hit_1(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv6_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = 2w1;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group ^ meta.multicast_metadata.bd_mrpf_group;
    }
    action multicast_route_bidir_star_g_hit_1(bit<16> mc_index, bit<16> mcast_rpf_group) {
        ipv6_multicast_route_star_g_stats.count();
        meta.multicast_metadata.mcast_mode = 2w2;
        meta.multicast_metadata.multicast_route_mc_index = mc_index;
        meta.multicast_metadata.mcast_route_hit = 1w1;
        meta.multicast_metadata.mcast_rpf_group = mcast_rpf_group | meta.multicast_metadata.bd_mrpf_group;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv6_metadata.lkp_ipv6_da: exact;
        }
        size = 1024;
        @name(".ipv6_multicast_route_star_g_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["ipv6_multicast_route_star_g"] = ipv6_multicast_route_star_g_content

nat_dst_content = '''
    action on_miss() {
    }
    action set_dst_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1w1;
    }
    table nat_dst {
        actions = {
            on_miss;
            set_dst_nat_nexthop_index;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
        }
        size = 1024;
    }'''
table_def["nat_dst"] = nat_dst_content

nat_flow_content = '''
    action set_dst_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1w1;
    }
    action nop() {
    }
    action set_src_nat_rewrite_index(bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
    }
    action set_twice_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1w1;
    }
    table nat_flow {
        actions = {
            nop;
            set_src_nat_rewrite_index;
            set_dst_nat_nexthop_index;
            set_twice_nat_nexthop_index;
        }
        key = {
            meta.l3_metadata.vrf          : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa: ternary;
            meta.ipv4_metadata.lkp_ipv4_da: ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.l3_metadata.lkp_l4_sport : ternary;
            meta.l3_metadata.lkp_l4_dport : ternary;
        }
        size = 512;
    }'''
table_def["nat_flow"] = nat_flow_content

nat_src_content = '''
    action on_miss() {
    }
    action set_src_nat_rewrite_index(bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            on_miss;
            set_src_nat_rewrite_index;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
        }
        size = 1024;
    }'''
table_def["nat_src"] = nat_src_content

nat_twice_content = '''
    action on_miss() {
    }
    action set_twice_nat_nexthop_index(bit<16> nexthop_index, bit<2> nexthop_type, bit<14> nat_rewrite_index) {
        meta.nat_metadata.nat_nexthop = nexthop_index;
        meta.nat_metadata.nat_nexthop_type = nexthop_type;
        meta.nat_metadata.nat_rewrite_index = nat_rewrite_index;
        meta.nat_metadata.nat_hit = 1w1;
    }
    table nat_twice {
        actions = {
            on_miss;
            set_twice_nat_nexthop_index;
        }
        key = {
            meta.l3_metadata.vrf          : exact;
            meta.ipv4_metadata.lkp_ipv4_sa: exact;
            meta.ipv4_metadata.lkp_ipv4_da: exact;
            meta.l3_metadata.lkp_ip_proto : exact;
            meta.l3_metadata.lkp_l4_sport : exact;
            meta.l3_metadata.lkp_l4_dport : exact;
        }
        size = 1024;
    }'''
table_def["nat_twice"] = nat_twice_content

meter_index_0_content = '''
    direct_meter<bit<2>>(MeterType.bytes) meter_index;
    action nop() {
    }
    action nop_2() {
        meter_index.read(meta.meter_metadata.packet_color);
    }
    table meter_index_0 {
        actions = {
            nop_2;
        }
        key = {
            meta.meter_metadata.meter_index: exact;
        }
        size = 1024;
        meters = meter_index;
    }'''
table_def["meter_index_0"] = meter_index_0_content

compute_ipv4_hashes_content = '''
    action compute_lkp_ipv4_hash() {
        hash(meta.hash_metadata.hash1, HashAlgorithm.crc16, (bit<16>)0, { meta.ipv4_metadata.lkp_ipv4_sa, meta.ipv4_metadata.lkp_ipv4_da, meta.l3_metadata.lkp_ip_proto, meta.l3_metadata.lkp_l4_sport, meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.l2_metadata.lkp_mac_sa, meta.l2_metadata.lkp_mac_da, meta.ipv4_metadata.lkp_ipv4_sa, meta.ipv4_metadata.lkp_ipv4_da, meta.l3_metadata.lkp_ip_proto, meta.l3_metadata.lkp_l4_sport, meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
    }
    table compute_ipv4_hashes {
        actions = {
            compute_lkp_ipv4_hash;
        }
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
    }'''
table_def["compute_ipv4_hashes"] = compute_ipv4_hashes_content

compute_ipv6_hashes_content = '''
    action compute_lkp_ipv6_hash() {
        hash(meta.hash_metadata.hash1, HashAlgorithm.crc16, (bit<16>)0, { meta.ipv6_metadata.lkp_ipv6_sa, meta.ipv6_metadata.lkp_ipv6_da, meta.l3_metadata.lkp_ip_proto, meta.l3_metadata.lkp_l4_sport, meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.l2_metadata.lkp_mac_sa, meta.l2_metadata.lkp_mac_da, meta.ipv6_metadata.lkp_ipv6_sa, meta.ipv6_metadata.lkp_ipv6_da, meta.l3_metadata.lkp_ip_proto, meta.l3_metadata.lkp_l4_sport, meta.l3_metadata.lkp_l4_dport }, (bit<32>)65536);
    }
    table compute_ipv6_hashes {
        actions = {
            compute_lkp_ipv6_hash;
        }
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
    }'''
table_def["compute_ipv6_hashes"] = compute_ipv6_hashes_content

compute_non_ip_hashes_content = '''
    action compute_lkp_non_ip_hash() {
        hash(meta.hash_metadata.hash2, HashAlgorithm.crc16, (bit<16>)0, { meta.ingress_metadata.ifindex, meta.l2_metadata.lkp_mac_sa, meta.l2_metadata.lkp_mac_da, meta.l2_metadata.lkp_mac_type }, (bit<32>)65536);
    }
    table compute_non_ip_hashes {
        actions = {
            compute_lkp_non_ip_hash;
        }
        key = {
            meta.ingress_metadata.drop_flag: exact;
        }
    }'''
table_def["compute_non_ip_hashes"] = compute_non_ip_hashes_content

compute_other_hashes_content = '''
    action computed_two_hashes() {
        meta.intrinsic_metadata.mcast_hash = (bit<13>)meta.hash_metadata.hash1;
        meta.hash_metadata.entropy_hash = meta.hash_metadata.hash2;
    }
    action computed_one_hash() {
        meta.hash_metadata.hash1 = meta.hash_metadata.hash2;
        meta.intrinsic_metadata.mcast_hash = (bit<13>)meta.hash_metadata.hash2;
        meta.hash_metadata.entropy_hash = meta.hash_metadata.hash2;
    }
    table compute_other_hashes {
        actions = {
            computed_two_hashes;
            computed_one_hash;
        }
        key = {
            meta.hash_metadata.hash1: exact;
        }
    }'''
table_def["compute_other_hashes"] = compute_other_hashes_content

meter_action_content = '''
    direct_counter(CounterType.packets) meter_stats;
    action meter_permit() {
    }
    action meter_deny() {
        mark_to_drop();
    }
    action meter_permit_0() {
        meter_stats.count();
    }
    action meter_deny_0() {
        meter_stats.count();
        mark_to_drop();
    }
    @name(".meter_action") table meter_action {
        actions = {
            meter_permit_0;
            meter_deny_0;
        }
        key = {
            meta.meter_metadata.packet_color: exact;
            meta.meter_metadata.meter_index : exact;
        }
        size = 1024;
        @name(".meter_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["meter_action"] = meter_action_content

ingress_bd_stats_0_content = '''
    @min_width(32) counter(32w1024, CounterType.packets_and_bytes) ingress_bd_stats;
    action update_ingress_bd_stats() {
        ingress_bd_stats.count((bit<32>)(bit<32>)meta.l2_metadata.bd_stats_idx);
    }
    table ingress_bd_stats_0 {
        actions = {
            update_ingress_bd_stats;
        }
        size = 1024;
    }'''
table_def["ingress_bd_stats_0"] = ingress_bd_stats_0_content

acl_stats_0_content = '''
    @min_width(16) counter(32w1024, CounterType.packets_and_bytes) acl_stats;
    action acl_stats_update() {
        acl_stats.count((bit<32>)(bit<32>)meta.acl_metadata.acl_stats_index);
    }
    table acl_stats_0 {
        actions = {
            acl_stats_update;
        }
        size = 1024;
    }'''
table_def["acl_stats_0"] = acl_stats_0_content

storm_control_stats_0_content = '''
    direct_counter(CounterType.packets) storm_control_stats;
    action nop() {
    }
    action nop_3() {
        storm_control_stats.count();
    }
    table storm_control_stats_0 {
        actions = {
            nop_3;
        }
        key = {
            meta.meter_metadata.packet_color: exact;
            standard_metadata.ingress_port  : exact;
        }
        size = 1024;
        @name(".storm_control_stats") counters = direct_counter(CounterType.packets);
    }'''
table_def["storm_control_stats_0"] = storm_control_stats_0_content

fwd_result_content = '''
    action nop() {
    }
    action set_l2_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.l2_metadata.l2_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.l2_metadata.l2_nexthop_type;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_fib_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.l3_metadata.fib_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.l3_metadata.fib_nexthop_type;
        meta.l3_metadata.routed = 1w1;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        meta.fabric_metadata.reason_code = 16w0x217;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_cpu_redirect_action() {
        meta.l3_metadata.routed = 1w0;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        standard_metadata.egress_spec = 9w64;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_acl_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.acl_metadata.acl_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.acl_metadata.acl_nexthop_type;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_racl_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.acl_metadata.racl_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.acl_metadata.racl_nexthop_type;
        meta.l3_metadata.routed = 1w1;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_nat_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.nat_metadata.nat_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.nat_metadata.nat_nexthop_type;
        meta.l3_metadata.routed = 1w1;
        meta.intrinsic_metadata.mcast_grp = 16w0;
        meta.fabric_metadata.dst_device = 8w0;
    }
    action set_multicast_route_action() {
        meta.fabric_metadata.dst_device = 8w127;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.intrinsic_metadata.mcast_grp = meta.multicast_metadata.multicast_route_mc_index;
        meta.l3_metadata.routed = 1w1;
        meta.l3_metadata.same_bd_check = 16w0xffff;
    }
    action set_multicast_bridge_action() {
        meta.fabric_metadata.dst_device = 8w127;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.intrinsic_metadata.mcast_grp = meta.multicast_metadata.multicast_bridge_mc_index;
    }
    action set_multicast_flood() {
        meta.fabric_metadata.dst_device = 8w127;
        meta.ingress_metadata.egress_ifindex = 16w65535;
    }
    action set_multicast_drop() {
        meta.ingress_metadata.drop_flag = 1w1;
        meta.ingress_metadata.drop_reason = 8w44;
    }
    table fwd_result {
        actions = {
            nop;
            set_l2_redirect_action;
            set_fib_redirect_action;
            set_cpu_redirect_action;
            set_acl_redirect_action;
            set_racl_redirect_action;
            set_nat_redirect_action;
            set_multicast_route_action;
            set_multicast_bridge_action;
            set_multicast_flood;
            set_multicast_drop;
        }
        key = {
            meta.l2_metadata.l2_redirect                 : ternary;
            meta.acl_metadata.acl_redirect               : ternary;
            meta.acl_metadata.racl_redirect              : ternary;
            meta.l3_metadata.rmac_hit                    : ternary;
            meta.l3_metadata.fib_hit                     : ternary;
            meta.nat_metadata.nat_hit                    : ternary;
            meta.l2_metadata.lkp_pkt_type                : ternary;
            meta.l3_metadata.lkp_ip_type                 : ternary;
            meta.multicast_metadata.igmp_snooping_enabled: ternary;
            meta.multicast_metadata.mld_snooping_enabled : ternary;
            meta.multicast_metadata.mcast_route_hit      : ternary;
            meta.multicast_metadata.mcast_bridge_hit     : ternary;
            meta.multicast_metadata.mcast_rpf_group      : ternary;
            meta.multicast_metadata.mcast_mode           : ternary;
        }
        size = 512;
    }'''
table_def["fwd_result"] = fwd_result_content
    
ecmp_group_content = '''
    action nop() {
    }
    action set_ecmp_nexthop_details(bit<16> ifindex, bit<16> bd, bit<16> nhop_index, bit<1> tunnel) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l3_metadata.nexthop_index = nhop_index;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
        meta.tunnel_metadata.tunnel_if_check = meta.tunnel_metadata.tunnel_terminate ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<16> bd, bit<16> uuc_mc_index, bit<16> nhop_index) {
        meta.intrinsic_metadata.mcast_grp = uuc_mc_index;
        meta.l3_metadata.nexthop_index = nhop_index;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table ecmp_group {
        actions = {
            nop;
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            meta.l3_metadata.nexthop_index: exact;
            meta.hash_metadata.hash1      : selector;
        }
        size = 1024;
        @name(".ecmp_action_profile") @mode("fair") implementation = action_selector(HashAlgorithm.identity, 32w1024, 32w10);
    }'''
table_def["ecmp_group"] = ecmp_group_content

nexthop_content = '''
    action set_nexthop_details(bit<16> ifindex, bit<16> bd, bit<1> tunnel) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
        meta.tunnel_metadata.tunnel_if_check = meta.tunnel_metadata.tunnel_terminate ^ tunnel;
    }
    action set_nexthop_details_for_post_routed_flood(bit<16> bd, bit<16> uuc_mc_index) {
        meta.intrinsic_metadata.mcast_grp = uuc_mc_index;
        meta.ingress_metadata.egress_ifindex = 16w0;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.fabric_metadata.dst_device = 8w127;
    }
    table nexthop {
        actions = {
            nop;
            set_nexthop_details;
            set_nexthop_details_for_post_routed_flood;
        }
        key = {
            meta.l3_metadata.nexthop_index: exact;
        }
        size = 1024;
    }'''
table_def["nexthop"] = nexthop_content

bd_flood_content = '''
    action nop() {
    }
    action set_bd_flood_mc_index(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp = mc_index;
    }
    table bd_flood {
        actions = {
            nop;
            set_bd_flood_mc_index;
        }
        key = {
            meta.ingress_metadata.bd     : exact;
            meta.l2_metadata.lkp_pkt_type: exact;
        }
        size = 1024;
    }'''
table_def["bd_flood"] = bd_flood_content

lag_group_content = '''
    action set_lag_miss() {
    }
    action set_lag_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action set_lag_remote_port(bit<8> device, bit<16> port) {
        meta.fabric_metadata.dst_device = device;
        meta.fabric_metadata.dst_port = port;
    }
    table lag_group {
        actions = {
            set_lag_miss;
            set_lag_port;
            set_lag_remote_port;
        }
        key = {
            meta.ingress_metadata.egress_ifindex: exact;
            meta.hash_metadata.hash2            : selector;
        }
        size = 1024;
        @name(".lag_action_profile") @mode("fair") implementation = action_selector(HashAlgorithm.identity, 32w1024, 32w8);
    }'''
table_def["lag_group"] = lag_group_content

learn_notify_content = '''
    @name(".nop") action nop() {
    }
    @name(".generate_learn_notify") action generate_learn_notify() {
        digest<mac_learn_digest>((bit<32>)1024, { meta.ingress_metadata.bd, meta.l2_metadata.lkp_mac_sa, meta.ingress_metadata.ifindex });
    }
    @name(".learn_notify") table learn_notify {
        actions = {
            nop;
            generate_learn_notify;
        }
        key = {
            meta.l2_metadata.l2_src_miss: ternary;
            meta.l2_metadata.l2_src_move: ternary;
            meta.l2_metadata.stp_state  : ternary;
        }
        size = 512;
    }'''
table_def["learn_notify"] = learn_notify_content

fabric_lag_content = '''
    action nop() {
    }
    action set_fabric_lag_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action set_fabric_multicast(bit<8> fabric_mgid) {
        meta.multicast_metadata.mcast_grp = meta.intrinsic_metadata.mcast_grp;
    }
    table fabric_lag {
        actions = {
            nop;
            set_fabric_lag_port;
            set_fabric_multicast;
        }
        key = {
            meta.fabric_metadata.dst_device: exact;
            meta.hash_metadata.hash2       : selector;
        }
        @name(".fabric_lag_action_profile") @mode("fair") implementation = action_selector(HashAlgorithm.identity, 32w1024, 32w8);
    }'''
table_def["fabric_lag"] = fabric_lag_content

traffic_class_content = '''
    action nop() {
    }
    action set_icos(bit<3> icos) {
        meta.intrinsic_metadata.ingress_cos = icos;
    }
    action set_queue(bit<5> qid) {
        meta.intrinsic_metadata.qid = qid;
    }
    action set_icos_and_queue(bit<3> icos, bit<5> qid) {
        meta.intrinsic_metadata.ingress_cos = icos;
        meta.intrinsic_metadata.qid = qid;
    }
    table traffic_class {
        actions = {
            nop;
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            meta.qos_metadata.tc_qos_group: ternary;
            meta.qos_metadata.lkp_tc      : ternary;
        }
        size = 512;
    }'''
table_def["traffic_class"] = traffic_class_content

drop_stats_0_content = '''
    counter(32w1024, CounterType.packets) drop_stats_2;
    action drop_stats_update() {
        drop_stats_2.count((bit<32>)(bit<32>)meta.ingress_metadata.drop_reason);
    }
    table drop_stats_0 {
        actions = {
            drop_stats_update;
        }
        size = 1024;
    }'''
table_def["drop_stats_0"] = drop_stats_0_content

system_acl_content = '''
    action nop() {
    }
    action copy_to_cpu(bit<5> qid, bit<32> meter_id, bit<3> icos) {
        meta.intrinsic_metadata.qid = qid;
        meta.intrinsic_metadata.ingress_cos = icos;
        clone3(CloneType.I2E, (bit<32>)32w250, { meta.ingress_metadata.bd, meta.ingress_metadata.ifindex, meta.fabric_metadata.reason_code, meta.ingress_metadata.ingress_port });
        copp.execute_meter((bit<32>)meter_id, meta.intrinsic_metadata.packet_color);
    }
    action redirect_to_cpu(bit<5> qid, bit<32> meter_id, bit<3> icos) {
        copy_to_cpu(qid, meter_id, icos);
        mark_to_drop();
        meta.fabric_metadata.dst_device = 8w0;
    }
    action copy_to_cpu_with_reason(bit<16> reason_code, bit<5> qid, bit<32> meter_id, bit<3> icos) {
        meta.fabric_metadata.reason_code = reason_code;
        copy_to_cpu(qid, meter_id, icos);
    }
    action redirect_to_cpu_with_reason(bit<16> reason_code, bit<5> qid, bit<32> meter_id, bit<3> icos) {
        copy_to_cpu_with_reason(reason_code, qid, meter_id, icos);
        mark_to_drop();
        meta.fabric_metadata.dst_device = 8w0;
    }
    action drop_packet() {
        mark_to_drop();
    }
    action drop_packet_with_reason(bit<32> drop_reason) {
        drop_stats.count((bit<32>)drop_reason);
        mark_to_drop();
    }
    action negative_mirror(bit<32> session_id) {
        clone3(CloneType.I2E, (bit<32>)session_id, { meta.ingress_metadata.ifindex, meta.ingress_metadata.drop_reason });
        mark_to_drop();
    }
    table system_acl {
        actions = {
            nop;
            redirect_to_cpu;
            redirect_to_cpu_with_reason;
            copy_to_cpu;
            copy_to_cpu_with_reason;
            drop_packet;
            drop_packet_with_reason;
            negative_mirror;
        }
        key = {
            meta.acl_metadata.if_label               : ternary;
            meta.acl_metadata.bd_label               : ternary;
            meta.ingress_metadata.ifindex            : ternary;
            meta.l2_metadata.lkp_mac_type            : ternary;
            meta.l2_metadata.port_vlan_mapping_miss  : ternary;
            meta.security_metadata.ipsg_check_fail   : ternary;
            meta.acl_metadata.acl_deny               : ternary;
            meta.acl_metadata.racl_deny              : ternary;
            meta.l3_metadata.urpf_check_fail         : ternary;
            meta.ingress_metadata.drop_flag          : ternary;
            meta.l3_metadata.l3_copy                 : ternary;
            meta.l3_metadata.rmac_hit                : ternary;
            meta.l3_metadata.routed                  : ternary;
            meta.ipv6_metadata.ipv6_src_is_link_local: ternary;
            meta.l2_metadata.same_if_check           : ternary;
            meta.tunnel_metadata.tunnel_if_check     : ternary;
            meta.l3_metadata.same_bd_check           : ternary;
            meta.l3_metadata.lkp_ip_ttl              : ternary;
            meta.l2_metadata.stp_state               : ternary;
            meta.ingress_metadata.control_frame      : ternary;
            meta.ipv4_metadata.ipv4_unicast_enabled  : ternary;
            meta.ipv6_metadata.ipv6_unicast_enabled  : ternary;
            meta.ingress_metadata.egress_ifindex     : ternary;
            meta.fabric_metadata.reason_code         : ternary;
        }
        size = 512;
    }'''
table_def["system_acl"] = system_acl_content

def main(argv):
    #Note1: ingress_qos_map_pcp & ingress_qos_map_dscp are disjoint
    #Note2: int_terminate & int_source are disjoint
    #Note3: int_sink_update_outer & int_source are disjoint
    #Note4: outer_ipv4_multicast outer_ipv4_multicast_star_g, && outer_ipv6_multicast, outer_ipv6_multicast_star_g are disjoint
    #Note5: ip_acl & ipv6_acl are disjoint
    #Note6: ipv4_urpf & ipv4_urpf_lpm are disjoint
    #Note7: ipv4_fib & ipv4_fib_lpm
    #Note8: ipv6_urpf & ipv6_urpf_lpm are disjoint
    #Note9: ipv6_fib & ipv6_fib_lpm are disjoint
    #Note10: ipv4_multicast_bridge & ipv4_multicast_bridge_star_g are disjoint
    #Note11: ipv4_multicast_route & ipv4_multicast_route_star_g are disjoint 
    #Note12: ipv6_multicast_bridge & ipv6_multicast_bridge_star_g are disjoint
    #Note13: ipv6_multicast_route & ipv6_multicast_route_star_g are disjoint 
    #Note14: nat_dst & nat_flow & nat_src & nat_twice are disjoint
    #Note15: compute_ipv4_hashes & compute_ipv6_hashes & compute_non_ip_hashes are disjoint
    #Note16: ecmp_group & nexthop are disjoint
    if len(argv) != 2:
        print("Usage: python3:", argv[0], "<number of tables you want>")
        sys.exit(1)
    num_of_selected = int(argv[1])
    total_table = len(table_list)
    random_list = random.sample(range(0, total_table), num_of_selected)
    random_list.sort()
    print(random_list)

if __name__ == "__main__":
    main(sys.argv)
