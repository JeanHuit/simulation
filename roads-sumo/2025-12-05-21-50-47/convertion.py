import xml.etree.ElementTree as ET

fcd_file = "fcd.xml"
tcl_out = "mobility.tcl"

tree = ET.parse(fcd_file)
root = tree.getroot()

with open(tcl_out, "w") as out:
    for timestep in root.findall("timestep"):
        t = float(timestep.get("time"))
        for vehicle in timestep.findall("vehicle"):
            vid = vehicle.get("id").replace("veh", "").replace("bus", "").replace("truck", "")
            x = float(vehicle.get("x"))
            y = float(vehicle.get("y"))

            out.write("$node_({}) set X_ {}\n".format(vid, x))
            out.write("$node_({}) set Y_ {}\n".format(vid, y))
            out.write("$node_({}) set Z_ 0\n".format(vid))
            out.write("$ns_ at {} \"$node_({}) setdest {} {} 0\"\n".format(t, vid, x, y))

print("Converted FCD → NS-2 mobility trace saved as mobility.tcl")
