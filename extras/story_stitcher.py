import uuid
import time
from typing import Optional

from pipeline.models import ThreatAlert, ThreatType

class StoryStitcher:
    """Attack Correlation & Story Building."""
    
    KILL_CHAIN_ORDER = [
        ThreatType.PORT_SCAN,
        ThreatType.ENCRYPTED_MALWARE,
        ThreatType.C2_BEACON,
        ThreatType.EXFILTRATION
    ]

    def __init__(self):
        self.stories: dict[str, dict] = {}
        self.alert_to_story: dict[str, str] = {}
        
    def _is_kill_chain_continuation(self, story: dict, alert: ThreatAlert) -> bool:
        """Check if alert continues the kill chain for the story."""
        if not story['threat_types']:
            return False
            
        story_types = story['threat_types']
        try:
            current_idx = self.KILL_CHAIN_ORDER.index(alert.threat_type)
        except ValueError:
            return False
            
        for prev_type in self.KILL_CHAIN_ORDER[:current_idx]:
            if prev_type in story_types:
                return True
        return False

    def correlate(self, alert: ThreatAlert) -> Optional[str]:
        """Check if this alert belongs to an existing story."""
        now = time.time()
        
        # Expire stories
        self._expire_stories()

        best_story_id = None

        for story_id, story in self.stories.items():
            if story.get('status') == 'closed':
                continue
            
            time_since_last = now - story['last_updated']
            
            # Same source IP and within 5 mins
            has_same_src = bool(set(alert.source_ips) & set(story['source_ips']))
            if has_same_src and time_since_last <= 300:
                best_story_id = story_id
                break
                
            # Same dest IP and related threat types and within 10 mins
            has_same_dst = bool(set(alert.dest_ips) & set(story['dest_ips']))
            if has_same_dst and time_since_last <= 600:
                best_story_id = story_id
                break
                
            # Kill chain correlation from same source
            if has_same_src and self._is_kill_chain_continuation(story, alert):
                best_story_id = story_id
                break

        if best_story_id:
            self._add_to_story(best_story_id, alert)
            return best_story_id

        return None

    def create_story(self, alert: ThreatAlert) -> str:
        """Create a new story with a UUID-based story_id."""
        story_id = f"STORY-{uuid.uuid4().hex[:12]}"
        now = time.time()
        self.stories[story_id] = {
            'story_id': story_id,
            'alert_ids': [alert.alert_id],
            'threat_types': [alert.threat_type],
            'source_ips': list(alert.source_ips),
            'dest_ips': list(alert.dest_ips),
            'start_time': now,
            'last_updated': now,
            'status': 'active'
        }
        self.alert_to_story[alert.alert_id] = story_id
        return story_id

    def _add_to_story(self, story_id: str, alert: ThreatAlert) -> None:
        """Add an alert to an existing story."""
        story = self.stories[story_id]
        story['alert_ids'].append(alert.alert_id)
        if alert.threat_type not in story['threat_types']:
            story['threat_types'].append(alert.threat_type)
        story['source_ips'] = list(set(story['source_ips'] + alert.source_ips))
        story['dest_ips'] = list(set(story['dest_ips'] + alert.dest_ips))
        story['last_updated'] = time.time()
        self.alert_to_story[alert.alert_id] = story_id

    def get_story(self, story_id: str) -> dict:
        """Return story summary."""
        return self.stories.get(story_id, {})

    def get_all_stories(self) -> list[dict]:
        """List all active stories."""
        self._expire_stories()
        return [story for story in self.stories.values() if story.get('status') == 'active']
        
    def _expire_stories(self) -> None:
        """Stories with no new alerts for 30 minutes are marked 'closed'."""
        now = time.time()
        for story in self.stories.values():
            if story.get('status') == 'active' and (now - story['last_updated']) > 1800:
                story['status'] = 'closed'
