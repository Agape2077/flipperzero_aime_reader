
# Flipper Zero aic/aime Card Reader Bridge

A Flipper Zero firmware bridge implementing a aime card reader protocol over USB CDC, enabling the device to function as a aime card reader for development and testing purposes.

## Features

- **Dual-Mode RF Polling**:
  - **ISO14443-3A**: Supports 13.56MHz identification and sector authentication.
  - **FeliCa**: Captures IDm and PMm from 212kHz/424kHz cards and mobile transit tokens.
- **Safe Hardware Bus Management**: Uses isolated background NFC threads and mutexes to prevent `BusFault` and hardware deadlocks.
- **Protocol Emulation**: Handles standard serial version handshakes, polling control, card detection, and key-auth routines.
- **Native RGB LED Control**: Syncs status color commands directly to the Flipper's rear LED.

## Project Structure

```text
aime_bridge/
├── application.fam
├── aime_reader.h
├── aime_reader.c
└── README.md
```

## Compilation and Flashing

Requires Python and uFBT:

```bash
pip install ufbt
ufbt launch
```
## Downloads

you can download pre-built binaries from the **Actions** tab at the top of this repository (select the latest successful build and grab the artifact).

## Python Test Script (`test_reader.py`)

```python
import serial
import time

ser = serial.Serial('COM3', 115200, timeout=0.3)

def send_packet(ser, addr, seq, cmd, payload=b''):
    frame_len = len(payload) + 5
    body = bytes([addr, seq, cmd, frame_len]) + payload
    checksum = sum(body) & 0xFF
    raw = bytes([0xE0]) + body + bytes([checksum])
    ser.write(raw)

def read_packet(ser):
    header = ser.read(1)
    if not header or header[0] != 0xE0:
        return None
    length = ser.read(1)[0]
    data = ser.read(length + 1)
    return {'cmd': hex(data[2]), 'status': hex(data[3]), 'payload': data[4:-1]}

send_packet(ser, 0x00, 0x01, 0x30)
print("FW Version:", read_packet(ser))

```
#
