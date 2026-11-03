import os
import socket
import struct
import time

# Konstanta ICMP
ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0


def checksum(source_string):
  """Menghitung checksum untuk paket ICMP."""
  sum = 0
  count_to = (len(source_string) // 2) * 2
  count = 0

  while count < count_to:
    val = source_string[count + 1] * 256 + source_string[count]
    sum = sum + val
    sum = sum & 0xFFFFFFFF
    count = count + 2

  if count_to < len(source_string):
    sum = sum + source_string[len(source_string) - 1]
    sum = sum & 0xFFFFFFFF

  sum = (sum >> 16) + (sum & 0xFFFF)
  sum = sum + (sum >> 16)
  answer = ~sum
  answer = answer & 0xFFFF
  answer = answer >> 8 | (answer << 8 & 0xFF00)
  return answer


def create_packet(id):
  """Membuat paket ICMP Echo Request."""
  # Header ICMP: type (8), code (8), checksum (16), id (16), sequence (16)
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, ICMP_CODE, 0, id, 1)
  data = struct.pack("d", time.time())
  # Hitung checksum pada data dan header kosong
  my_checksum = checksum(header + data)
  # Header dengan checksum yang benar
  header = struct.pack(
      "bbHHh", ICMP_ECHO_REQUEST, ICMP_CODE, socket.htons(my_checksum), id, 1
  )
  return header + data


def ping(dest_addr, timeout=2):
  """Mengirimkan ICMP Ping ke alamat tujuan."""
  # Buat raw socket (membutuhkan hak akses administrator/root di beberapa OS)
  icmp = socket.getprotobyname("icmp")
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
  except PermissionError:
    print(
        "❌ Error: Program membutuhkan hak akses Administrator / Root untuk"
        " membuat Raw Socket."
    )
    return

  dest_ip = socket.gethostbyname(dest_addr)
  print(f"\nPinging {dest_addr} [{dest_ip}] dengan Python ICMP:")

  my_id = os.getpid() & 0xFFFF
  packet = create_packet(my_id)
  sock.sendto(packet, (dest_ip, 1))

  start_time = time.time()
  sock.settimeout(timeout)

  try:
    eval_packet, addr = sock.recvfrom(1024)
    time_received = time.time()
    # Ambil waktu round trip
    rtt = (time_received - start_time) * 1000
    print(f"Reply dari {addr[0]}: waktu={rtt:.2f}ms")
  except socket.timeout:
    print("❌ Request timed out.")
  finally:
    sock.close()


if __name__ == "__main__":
  # Contoh target: Google DNS
  target = "8.8.8.8"
  ping(target)