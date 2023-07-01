import hashlib
import parser.pidgen.bink as bink
import pefile


def bink_out(resource_data):
    # Process the resource data
    # bink_id = "%02x" % int.from_bytes(resource_data[0x00:0x04], 'little')
    sha1_hash = hashlib.sha1(resource_data).hexdigest()
    data = bink.parse(resource_data)
    data["sha1_hash"] = sha1_hash

    return data


def parse(file_data):
    output = {}

    found_bink = 0
    # attempt extracting via the PE directory
    try:
        # Load the DLL using pefile
        pe = pefile.PE(data=file_data)

        # Loop over the resources in the DLL
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None and resource_type.name.string.decode() == 'BINK':
                found_bink = 1
                # Extract resources from the "BINK" resource type
                for resource_id_entry in resource_type.directory.entries:
                    for resource_entry in resource_id_entry.directory.entries:
                        resource_offset = resource_entry.data.struct.OffsetToData
                        resource_size = resource_entry.data.struct.Size

                        # Access the resource data
                        resource_data = pe.get_memory_mapped_image()[resource_offset: resource_offset + resource_size]

                        bink_id = "%08x" % int.from_bytes(resource_data[0x00:0x04], 'little')
                        output[bink_id] = bink_out(resource_data)

        # Close the PE file
        pe.close()
    except pefile.PEFormatError as e:
        found_bink = 0
    except AttributeError as e:
        found_bink = 0

    # attempt a string search
    if found_bink == 0:

        string_1998 = b'\xAE\xDF\x30\x01'
        string_2002 = b'\xC4\x7C\x31\x01'
        entries = {}
        for i in range(len(file_data) - 3):
            if ((file_data[i:i + 4] == string_1998 and i + 0x170 < len(file_data) and (
                    file_data[i + 0x170:i + 0x170 + 4] == string_1998)) or (
                    file_data[i:i + 4] == string_1998 and i - 0x170 > 0 and (
                    file_data[i - 0x170:i - 0x170 + 4] == string_1998))):
                start = i - 16
                end = start + int.from_bytes(file_data[start + 4:start + 8], 'little') + 4
                entries[start] = {
                    "Type": "BINK1998",
                    "StartAddress": start,
                    "EndAddress": end
                }

            if ((file_data[i:i + 4] == string_1998 and i + 0x180 < len(file_data) and (
                    file_data[i + 0x180:i + 0x180 + 4] == string_1998)) or (
                    file_data[i:i + 4] == string_1998 and i - 0x180 > 0 and (
                    file_data[i - 0x180:i - 0x180 + 4] == string_1998))):
                start = i - 16
                end = start + int.from_bytes(file_data[start + 4:start + 8], 'little') + 4
                entries[start] = {
                    "Type": "BINK1998",
                    "StartAddress": start,
                    "EndAddress": end
                }

            elif file_data[i:i + 4] == string_2002 and i + 0x1E8 < len(file_data) and (
                    file_data[i + 0x1E8:i + 0x1E8 + 4] == string_2002):
                start = i - 16
                end = start + int.from_bytes(file_data[start + 4:start + 8], 'little') + 4
                entries[start] = {
                    "Type": "BINK2002",
                    "StartAddress": start,
                    "EndAddress": end
                }

        if len(entries) != 0:
            for key, value in entries.items():
                bink_data = file_data[key:value['EndAddress']]
                bink_id = "%08x" % int.from_bytes(bink_data[0x00:0x04], 'little')
                output[bink_id] = bink_out(bink_data)

    return output
