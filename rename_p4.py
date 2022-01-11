import sys

def main(argv):
    if len(argv) != 2:
        print("Usage: python3", argv[0], "<input p4 file>")
        sys.exit(1)
    input_file = argv[1]
    rename_dir = {} # key: variable name in p4, val: renamed variable name
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
        out_str += line
    print(out_str)
    print(rename_dir)

if __name__ == '__main__':
    main(sys.argv)
