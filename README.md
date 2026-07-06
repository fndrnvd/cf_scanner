python run.py --top 15 --count 1000 --output Top_15_Ips.txt

Switches:

  --top N
      Number of best IPs to output.
      Default: 5

  --count N
      Number of random IPs to generate and test.
      Default: 500

  --prefer-ipv6
      Prefer IPv6 addresses when generating IPs (flag).
      Default: off (IPv4 preferred)

  --no-speed-test
      Skip the download speed test (flag).
      Default: off (speed test runs)

  --output FILE
      Save the comma-separated IP list to a file.
      Default: none (no file written)

  --verbose
      Print detailed JSON report of top IPs (flag).
      Default: off
