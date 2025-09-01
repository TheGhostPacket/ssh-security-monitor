import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import random

class SSHLogAnalyzer:
    def __init__(self):
        """Initialize the SSH log analyzer with sample data"""
        self.sample_logs = self.generate_sample_logs()
        self.parsed_logs = self.parse_logs()
        
    def generate_sample_logs(self):
        """Generate realistic SSH log entries for demonstration"""
        # Common attack IPs (using example IPs for demo)
        attack_ips = [
            '203.0.113.1', '198.51.100.42', '192.0.2.146', 
            '203.0.113.25', '198.51.100.88', '192.0.2.233',
            '185.220.101.182', '45.148.10.124', '89.248.165.2'
        ]
        
        # Common usernames attackers try
        common_users = ['root', 'admin', 'user', 'test', 'guest', 'oracle', 'postgres', 'mysql']
        
        # Generate logs for the last 7 days
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        # Generate failed attempts (attacks)
        for day in range(7):
            current_day = base_time + timedelta(days=day)
            
            # Generate 20-50 failed attempts per day
            for _ in range(random.randint(20, 50)):
                time_offset = timedelta(
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
                log_time = current_day + time_offset
                
                ip = random.choice(attack_ips)
                user = random.choice(common_users)
                pid = random.randint(1000, 9999)
                
                log_entry = f"{log_time.strftime('%b %d %H:%M:%S')} server sshd[{pid}]: Failed password for {user} from {ip} port 22 ssh2"
                logs.append(log_entry)
                
                # Sometimes add invalid user attempts
                if random.random() < 0.3:
                    fake_user = random.choice(['administrator', 'support', 'backup', 'deploy'])
                    log_entry2 = f"{log_time.strftime('%b %d %H:%M:%S')} server sshd[{pid}]: Invalid user {fake_user} from {ip} port 22"
                    logs.append(log_entry2)
        
        # Add some successful logins (legitimate users)
        legitimate_ips = ['192.168.1.100', '10.0.0.45', '172.16.1.200']
        legitimate_users = ['sysadmin', 'developer', 'backup']
        
        for _ in range(15):  # Some successful logins
            time_offset = timedelta(
                days=random.randint(0, 6),
                hours=random.randint(8, 18),  # Business hours
                minutes=random.randint(0, 59)
            )
            log_time = base_time + time_offset
            
            ip = random.choice(legitimate_ips)
            user = random.choice(legitimate_users)
            pid = random.randint(1000, 9999)
            
            log_entry = f"{log_time.strftime('%b %d %H:%M:%S')} server sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"
            logs.append(log_entry)
        
        # Sort by timestamp
        return sorted(logs)
    
    def parse_logs(self):
        """Parse SSH log entries into structured data"""
        parsed = []
        
        # Patterns for different types of SSH events
        failed_password_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[(\d+)\]:\s+Failed password for (\w+) from ([\d.]+) port (\d+)'
        invalid_user_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[(\d+)\]:\s+Invalid user (\w+) from ([\d.]+) port (\d+)'
        accepted_password_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+sshd\[(\d+)\]:\s+Accepted password for (\w+) from ([\d.]+) port (\d+)'
        
        for log_line in self.sample_logs:
            # Try to match failed password attempts
            match = re.search(failed_password_pattern, log_line)
            if match:
                timestamp, pid, username, ip, port = match.groups()
                parsed.append({
                    'timestamp': self.parse_timestamp(timestamp),
                    'event_type': 'failed_password',
                    'username': username,
                    'source_ip': ip,
                    'port': int(port),
                    'pid': int(pid)
                })
                continue
            
            # Try to match invalid user attempts
            match = re.search(invalid_user_pattern, log_line)
            if match:
                timestamp, pid, username, ip, port = match.groups()
                parsed.append({
                    'timestamp': self.parse_timestamp(timestamp),
                    'event_type': 'invalid_user',
                    'username': username,
                    'source_ip': ip,
                    'port': int(port),
                    'pid': int(pid)
                })
                continue
            
            # Try to match successful logins
            match = re.search(accepted_password_pattern, log_line)
            if match:
                timestamp, pid, username, ip, port = match.groups()
                parsed.append({
                    'timestamp': self.parse_timestamp(timestamp),
                    'event_type': 'accepted_password',
                    'username': username,
                    'source_ip': ip,
                    'port': int(port),
                    'pid': int(pid)
                })
        
        return parsed
    
    def parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object"""
        try:
            # Add current year since logs don't include year
            current_year = datetime.now().year
            full_timestamp = f"{current_year} {timestamp_str}"
            return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except:
            return datetime.now()
    
    def get_attack_stats(self):
        """Get overall attack statistics"""
        failed_attempts = [log for log in self.parsed_logs if log['event_type'] in ['failed_password', 'invalid_user']]
        successful_logins = [log for log in self.parsed_logs if log['event_type'] == 'accepted_password']
        
        # Get unique attacking IPs
        attacking_ips = set(log['source_ip'] for log in failed_attempts)
        
        # Calculate attack frequency (last 24 hours)
        last_24h = datetime.now() - timedelta(hours=24)
        recent_attacks = [log for log in failed_attempts if log['timestamp'] >= last_24h]
        
        return {
            'total_failed_attempts': len(failed_attempts),
            'total_successful_logins': len(successful_logins),
            'unique_attacking_ips': len(attacking_ips),
            'attacks_last_24h': len(recent_attacks),
            'most_targeted_users': self.get_most_targeted_users(),
            'attack_success_rate': round((len(successful_logins) / (len(failed_attempts) + len(successful_logins))) * 100, 2) if (len(failed_attempts) + len(successful_logins)) > 0 else 0
        }
    
    def get_most_targeted_users(self):
        """Get most frequently targeted usernames"""
        failed_attempts = [log for log in self.parsed_logs if log['event_type'] in ['failed_password', 'invalid_user']]
        user_counts = Counter(log['username'] for log in failed_attempts)
        return [{'username': user, 'attempts': count} for user, count in user_counts.most_common(5)]
    
    def get_attacks_timeline(self):
        """Get timeline of attacks for charting"""
        failed_attempts = [log for log in self.parsed_logs if log['event_type'] in ['failed_password', 'invalid_user']]
        
        # Group by hour
        hourly_attacks = defaultdict(int)
        for log in failed_attempts:
            hour_key = log['timestamp'].strftime('%Y-%m-%d %H:00')
            hourly_attacks[hour_key] += 1
        
        # Convert to format suitable for Chart.js
        timeline = []
        for hour, count in sorted(hourly_attacks.items()):
            timeline.append({
                'time': hour,
                'attacks': count
            })
        
        return timeline
    
    def get_top_attackers(self):
        """Get top attacking IPs with mock geolocation data"""
        failed_attempts = [log for log in self.parsed_logs if log['event_type'] in ['failed_password', 'invalid_user']]
        
        # Count attacks per IP
        ip_counts = Counter(log['source_ip'] for log in failed_attempts)
        
        # Mock geolocation data for demo (in real app, you'd use GeoIP database)
        mock_locations = {
            '203.0.113.1': {'country': 'Russia', 'city': 'Moscow', 'lat': 55.7558, 'lng': 37.6173},
            '198.51.100.42': {'country': 'China', 'city': 'Beijing', 'lat': 39.9042, 'lng': 116.4074},
            '192.0.2.146': {'country': 'North Korea', 'city': 'Pyongyang', 'lat': 39.0392, 'lng': 125.7625},
            '203.0.113.25': {'country': 'Iran', 'city': 'Tehran', 'lat': 35.6892, 'lng': 51.3890},
            '198.51.100.88': {'country': 'Romania', 'city': 'Bucharest', 'lat': 44.4268, 'lng': 26.1025},
            '192.0.2.233': {'country': 'Brazil', 'city': 'São Paulo', 'lat': -23.5505, 'lng': -46.6333},
            '185.220.101.182': {'country': 'Ukraine', 'city': 'Kiev', 'lat': 50.4501, 'lng': 30.5234},
            '45.148.10.124': {'country': 'Turkey', 'city': 'Istanbul', 'lat': 41.0082, 'lng': 28.9784},
            '89.248.165.2': {'country': 'Poland', 'city': 'Warsaw', 'lat': 52.2297, 'lng': 21.0122}
        }
        
        attackers = []
        for ip, count in ip_counts.most_common(10):
            location = mock_locations.get(ip, {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lng': 0})
            attackers.append({
                'ip': ip,
                'attempts': count,
                'country': location['country'],
                'city': location['city'],
                'latitude': location['lat'],
                'longitude': location['lng']
            })
        
        return attackers
    
    def get_attack_methods(self):
        """Get breakdown of attack methods"""
        failed_passwords = len([log for log in self.parsed_logs if log['event_type'] == 'failed_password'])
        invalid_users = len([log for log in self.parsed_logs if log['event_type'] == 'invalid_user'])
        
        return {
            'brute_force': failed_passwords,
            'user_enumeration': invalid_users,
            'total_attacks': failed_passwords + invalid_users
        }
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        stats = self.get_attack_stats()
        top_attackers = self.get_top_attackers()[:5]  # Top 5 attackers
        attack_methods = self.get_attack_methods()
        
        # Calculate risk level
        attacks_24h = stats['attacks_last_24h']
        if attacks_24h > 100:
            risk_level = "HIGH"
            risk_color = "#ef4444"
        elif attacks_24h > 50:
            risk_level = "MEDIUM" 
            risk_color = "#f59e0b"
        else:
            risk_level = "LOW"
            risk_color = "#10b981"
        
        # Security recommendations
        recommendations = [
            "Change SSH default port from 22 to a custom port",
            "Implement fail2ban to automatically block attacking IPs",
            "Disable root login via SSH",
            "Use SSH key authentication instead of passwords",
            "Enable two-factor authentication (2FA)",
            "Set up intrusion detection system (IDS)",
            "Regular security monitoring and log analysis"
        ]
        
        return {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': stats,
            'risk_assessment': {
                'level': risk_level,
                'color': risk_color,
                'score': min(100, attacks_24h * 2)  # Simple risk scoring
            },
            'top_threats': top_attackers,
            'attack_methods': attack_methods,
            'recommendations': recommendations,
            'total_events_analyzed': len(self.parsed_logs)
        }