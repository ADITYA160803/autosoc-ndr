#!/usr/bin/env python3
"""
Attack Chain Linking Agent
Connects isolated security events into attack campaigns
"""

from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any

class AttackChainBuilder:
    def __init__(self):
        self.campaigns = []

    def link_events(self, events: List[Dict]) -> List[Dict]:
        """
        Group events into campaigns based on shared indicators (IPs)
        """
        if not events:
            return []

        # Find unique entities (IPs) involved in each event
        entity_to_events = defaultdict(list)
        for i, event in enumerate(events):
            src = event.get('src_ip')
            dst = event.get('dst_ip')
            
            if src and src != 'multiple' and src != 'unknown':
                entity_to_events[src].append(i)
            if dst and dst != 'multiple' and dst != 'unknown':
                entity_to_events[dst].append(i)

        # Basic clustering: if events share an entity, they are in the same campaign
        # (This is a simplified version of a connected components algorithm)
        visited = set()
        campaigns = []

        for i in range(len(events)):
            if i in visited:
                continue
            
            # Start a new campaign
            current_campaign_indices = {i}
            queue = [i]
            visited.add(i)
            
            while queue:
                curr_idx = queue.pop(0)
                event = events[curr_idx]
                
                # Entities in this event
                entities = []
                src = event.get('src_ip')
                dst = event.get('dst_ip')
                if src and src != 'multiple': entities.append(src)
                if dst and dst != 'multiple': entities.append(dst)
                
                for entity in entities:
                    for neighbor_idx in entity_to_events[entity]:
                        if neighbor_idx not in visited:
                            visited.add(neighbor_idx)
                            current_campaign_indices.add(neighbor_idx)
                            queue.append(neighbor_idx)
            
            # Build campaign object
            campaign_events = [events[idx] for idx in sorted(list(current_campaign_indices))]
            start_time = min(e.get('timestamp', 0) for e in campaign_events)
            end_time = max(e.get('timestamp', 0) for e in campaign_events)
            
            # Identify main actors
            threat_actors = set()
            targets = set()
            for e in campaign_events:
                if e.get('event_type') == 'scan_attack':
                    threat_actors.add(e.get('src_ip'))
                elif e.get('event_type') == 'ddos_attack':
                    targets.add(e.get('dst_ip'))
                elif e.get('event_type') == 'c2_beaconing':
                    threat_actors.add(e.get('src_ip'))
                    targets.add(e.get('dst_ip'))

            campaigns.append({
                "id": f"CAMP-{len(campaigns)+1:03d}",
                "events": campaign_events,
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": round(end_time - start_time, 2),
                "event_types": list(set(e.get('event_type', 'unknown') for e in campaign_events)),
                "threat_actors": list(threat_actors),
                "targets": list(targets),
                "severity": self._get_max_severity([e.get('severity', 'LOW') for e in campaign_events])
            })

        return campaigns

    def _get_max_severity(self, severities: List[str]) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return min(severities, key=lambda s: order.get(s, 4)) if severities else "LOW"


def print_campaign_summary(campaigns: List[Dict]) -> None:
    """Print summary of attack campaigns"""
    if not campaigns:
        print("\n  No multi-stage attack campaigns identified.\n")
        return
    
    print("\n" + "=" * 70)
    print("  ⛓️ ATTACK CAMPAIGNS (CORRELATED EVENTS)")
    print("=" * 70)
    
    for camp in campaigns:
        severity = camp.get("severity", "MEDIUM")
        print(f"\n  [{severity}] {camp.get('id')} - {', '.join(camp.get('event_types'))}")
        print(f"    Duration: {camp.get('duration_seconds')}s")
        if camp.get("threat_actors"):
            print(f"    Possible Threat Actor(s): {', '.join(camp.get('threat_actors'))}")
        if camp.get("targets"):
            print(f"    Target(s): {', '.join(camp.get('targets'))}")
        print(f"    Connected Events: {len(camp.get('events'))}")
        
        for i, event in enumerate(camp.get('events'), 1):
            print(f"      {i}. {event.get('severity')} - {event.get('event_type')}")
        
    print("\n" + "=" * 70)
    print(f"  Total Campaigns: {len(campaigns)}")
    print("=" * 70 + "\n")
