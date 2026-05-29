from pcap.parser import read_all_packets
from pcap.aggregator import aggregate_flows
from pcap.extractor import extract_iocs_from_flows
from detection.engine import run_detection, print_alerts_summary

print('[*] Loading PCAP...')
packets = read_all_packets('sample_data/lumma.pcap')

print('[*] Aggregating flows...')
flows = aggregate_flows(packets)

print('[*] Extracting IOCs...')
iocs = extract_iocs_from_flows(flows)

print('[*] Running detection rules...')
alerts = run_detection(flows, iocs)

print_alerts_summary(alerts)
