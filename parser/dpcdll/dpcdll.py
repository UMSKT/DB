from struct import unpack


def read_int(data, offset):
    return unpack('<I', data[offset:offset + 4])[0]


def parse(file_data):
    lic_types = ['NULL', 'Volume', 'Retail', 'Evaluation', 'Tablet', 'OEM', 'Embedded']

    dpc_data = {}

    tmp = file_data
    offset = tmp.find(b'\x00\x00\x00\xff\xff\xff\x7f\x80') - 21
    del tmp

    if offset == -22:
        raise ValueError('Offset not found')

    while file_data[offset:offset + 4] != b'\x00\x00\x00\x00':
        offset -= 164

    offset -= 4

    while True:
        if offset < 0 or offset + 32 >= len(file_data):
            raise ValueError('Error in offset or not enough data')

        ind = read_int(file_data, offset)
        bink_id = hex(read_int(file_data, offset + 4)).zfill(4).upper()
        min_pid = read_int(file_data, offset + 8)
        max_pid = read_int(file_data, offset + 12)

        if min_pid > 999 or max_pid > 999:
            break

        lic_type = read_int(file_data, offset + 16)

        if lic_type > 6:
            break

        days_to_act = str(read_int(file_data, offset + 20))
        eval_days = str(read_int(file_data, offset + 24))
        sig_len = read_int(file_data, offset + 28)

        if offset + 32 + sig_len >= len(file_data):
            raise ValueError('Error in signature length or not enough data')

        offset += 32 + sig_len

        if bink_id not in dpc_data:
            dpc_data[bink_id] = []

        dpc_data[bink_id].append({
            'Type': lic_types[lic_type],
            'PIDRange': [min_pid, max_pid],
            'EvaluationDays': eval_days,
            'ActivationGraceDays': days_to_act
        })

    return dpc_data
