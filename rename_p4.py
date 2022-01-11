import sys

'''input: number of packets used, output: a series of bit<32> pkt_{i};'''
def pkt_def(cnt):
    ret_str = ""
    for i in range(cnt):
        ret_str += "bit<32> pkt_" + str(i) + ";\n"
    return ret_str

def apply_tbl(table_list):
    ret_str = "    apply {\n"
    for table in table_list:
        ret_str += "        " + table + ".apply();\n"
    ret_str += "    }\n"
    return ret_str

def main(argv):
    if len(argv) != 2:
        print("Usage: python3", argv[0], "<input p4 file>")
        sys.exit(1)
    input_file = argv[1]
    rename_dir = {} # key: variable name in p4, val: renamed variable name
    table_list = []
    cnt = 0
    f = open(input_file, "r")
    out_str = ""
    for line in f:
        # Deal with the assignment in action block
        if line.find("=") != -1 and line.find("{") == -1:
            l = line.split()
            for var in l:
                if var.find(".") != -1:
                    if var not in rename_dir:
                        rename_dir[var] = "hdr.pkts.pkt_" + str(cnt)
                        cnt = cnt + 1
                    line = line.replace(var, rename_dir[var])
        # Deal with the match part
        elif line.find(":") != -1:
            pos = line.find(":")
            if line[pos - 1] != ' ':
                line = line[:pos] + ' ' + line[pos:]
            l = line.split()
            for var in l:
                if var.find(".") != -1:
                    if var not in rename_dir:
                        rename_dir[var] = "hdr.pkts.pkt_" + str(cnt)
                        cnt = cnt + 1
                    line = line.replace(var, rename_dir[var])
        elif line.find("table") != -1:
            l = line.split()
            table_name = l[1]
            table_list.append(table_name)
        out_str += line
    print(out_str)
    out_prog = '''#include <core.p4>
#include <v1model.p4>
header packets_t {
'''
    # add packet fields definition
    out_prog += pkt_def(cnt)
    out_prog += '''struct headers {
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
    '''
    out_prog += out_str
    #add a series of apply
    out_prog += apply_tbl(table_list) 
    out_prog += '''}

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
) main;'''

    print(out_prog)

if __name__ == '__main__':
    main(sys.argv)
