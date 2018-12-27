from opcuapen.attacks import paddings

def test_pkcs1v15():
    padded_bytes = paddings.pad_pkcs1v15(148*b'\xff')
    assert(len(padded_bytes) == 256)
    assert padded_bytes == b'\x00\x02' + 105 * b'\x01' + b'\x00' + 148 * b'\xff'
