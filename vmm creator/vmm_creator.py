"""
script to automatically create vmm config from yaml file and a template
author: Mohamed Ali
email: mohamedm@juniper.net
"""
import os
import argparse
import jinja2
import yaml


def load_temp(fname):
    """
    Load jinja2 template
    """
    b_name = os.path.dirname(os.path.abspath(fname))
    f_name = os.path.basename(os.path.abspath(fname))
    environment = jinja2.Environment(
        trim_blocks=True, lstrip_blocks=True, loader=jinja2.FileSystemLoader(b_name)
    )
    template = environment.get_template(f_name)
    return template


def load_yml(fname):
    """
    Load yaml file
    """
    with open(fname, "r", encoding="utf-8") as f:
        topology = yaml.safe_load(f)
    return topology


def update_params_disks(p):
    """
    add disks
    """
    disks = {}
    for dev in p["devices"]:
        disks[dev["name"]] = (dev["img"], dev["type"])
    p["disks"] = disks


def update_params_bridges(p):
    """
    add bridges
    """
    bridges = []
    for dev in p["devices"]:
        for fpc in dev["fpcs"]:
            for i, link in enumerate(fpc["links"]):
                new_link = "".join(sorted(list((link + dev["name"]).lower())))
                for f in dev["fpcs"]:
                    while new_link in f["links"]:
                        new_link = new_link + "1"
                fpc["links"][i] = new_link
                bridges.append(new_link)
    p["bridges"] = list(set(bridges))


def update_params_types(p):
    """
    add devices' types
    """
    types = []
    for dev in p["devices"]:
        types.append(dev["type"])
    p["types"] = list(set(types))


def render_temp(t, p):
    """
    render the template
    """
    conf = t.render(p)
    with open(f"{p['name']}.cfg", "w", encoding="utf-8") as f:
        f.writelines(conf)


def update_vm_names(p):
    """
    update vm names to upper
    """
    for dev in p["devices"]:
        dev["name"] = dev["name"].upper()


def sanity_checks(p):
    """
    Checks for config problem
    """
    for dev in p["devices"]:
        if not ("re" in dev):
            dev["re"] = 1
        if dev["re"] > 2 or dev["re"] < 1:
            print(f"Wrong number of REs for {dev['name']} for type {dev['type']}.")
            return False
        if not ("mem" in dev):
            dev["mem"] = 4
        if dev["mem"] < 1:
            print(f"Memory is too low for {dev['name']} for type {dev['type']}.")
            return False
    if "vbrackla" in p["types"] and "vscapa" in p["types"]:
        print("cant have both vbrackla and vscapa at same time in topology")
        return False
    elif "vbrackla" in p["types"] and "vardberg" in p["types"]:
        print("cant have both vbrackla and vardberg at same time in topology")
        return False
    elif "vscapa" in p["types"] and "vardberg" in p["types"]:
        print("cant have both vscapa and vardberg at same time in topology")
        return False
    else:
        return True


def main():
    """
    main func
    """
    parser = argparse.ArgumentParser(description="convert yaml file to vmm config file")
    parser.add_argument("-f", "--file", required=True, help="yaml file")
    args = parser.parse_args()
    yml_file = args.file
    temp_file = "vmm_template.j2"
    temp = load_temp(temp_file)
    parms = load_yml(yml_file)
    update_vm_names(parms)
    update_params_disks(parms)
    update_params_bridges(parms)
    update_params_types(parms)
    if sanity_checks(parms):
        render_temp(temp, parms)
    else:
        print("script failed due to constraints")
        return


if __name__ == "__main__":
    main()
