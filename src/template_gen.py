import os
import stat
import glob
from collections import defaultdict

# takes the path and returns the major and minor values
def get_major_minor_from_dev(path):
    try:
        st = os.stat(path)
        if not stat.S_ISCHR(st.st_mode):
            return None
        return (path, os.major(st.st_rdev), os.minor(st.st_rdev))
    except:
        return None

# walks through if found a directory, when file found then will get the info using - get_major_minor_from_dev()
def iter_paths(paths=["/dev/input", "/dev/tty", "/dev/pts"]):
    output = []
    paths.extend(glob.glob("/dev/hidraw*"))
    for p in paths:
        if not os.path.exists(p):
            continue
        if not os.path.isdir(p):
            res = get_major_minor_from_dev(p)
            if res:
                output.append(res)
            continue
        for root, _, files in os.walk(p):
            for name in files:
                full_path = os.path.join(root, name)
                res = get_major_minor_from_dev(full_path)
                if res:
                    output.append(res)
    return output

# takes the minor values of devices and group them together into - (start, end) ranges
def group_minor_values(minors):
    minors = sorted(set(minors))
    if not minors:
        return []
    ranges = []
    start = end = minors[0]
    for m in minors[1:]:
        if m == end + 1:
            end = m
        else:
            ranges.append((start, end))
            start = end = m
    ranges.append((start, end))
    return ranges

# returns major value and its corresponding minor values like 12[3,4,53] 4[0,5]..
def generate_mm():
    out = iter_paths()
    paths_to_check = ["/dev/input", "/dev/tty", "/dev/pts", "/dev/hidraw"]
    values = []
    for p in out:
        for path in paths_to_check:
            if p[0].startswith(path):
                values.append((path, p[1], p[2]))
    grouped = defaultdict(list)
    for _, major, minor in values:
        grouped[major].append(minor)
    return grouped

# generates the C code part that need to updated in the bpf program
def generate_condition(grouped):
    conds = []
    for major, minor_list in grouped.items():
        ranges = group_minor_values(minor_list)
        for r_start, r_end in ranges:
            if r_start == r_end:
                conds.append(f"(major == {major} && minor == {r_start})")
            else:
                conds.append(f"(major == {major} && minor >= {r_start} && minor <= {r_end})")
    return " || \\\n    ".join(conds)


def inject_into_bpf(bpf_file="test.bpf.c"):
    grouped = generate_mm()
    condition_block = generate_condition(grouped)

    new_code = f"""\
  // __AUTOGENERATE_DEVICE_FILTER__
  if (
    {condition_block}
  ) {{
    bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);
    struct event_t ev = {{
        .pid = pid,
        .major = major,
        .minor = minor,
    }};
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }}
  return 0;
"""
    with open(bpf_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    in_autogen = False
    for line in lines:
        if '// __AUTOGENERATE_DEVICE_FILTER__' in line:
            new_lines.append(new_code)
            in_autogen = True
            continue
        if in_autogen:
            if 'return 0;' in line or line.strip() == '}':
                in_autogen = False
            continue
        new_lines.append(line)

    with open(bpf_file, 'w') as f:
        f.writelines(new_lines)

    print(f"[INFO] Injected dynamic device filter data into {bpf_file}.")

if __name__ == '__main__':
    # inject_into_bpf()
    # print(iter_paths())
    out = generate_mm()
    for major, minor in out.items():
        print(group_minor_values(minor))
