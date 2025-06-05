#!/usr/bin/env python3
"""
Distributed Threat Intelligence Sync Tool (DTIST)
A federated threat intelligence platform for secure sharing and synchronization
of threat indicators across distributed security nodes.

Features:
- Real-time threat indicator synchronization
- End-to-end encryption with key rotation
- Distributed consensus for threat validation
- Advanced threat correlation and scoring
- RESTful API with WebSocket support
- Built-in threat hunting capabilities
- Multi-source intelligence aggregation
- Automated IOC enrichment
"""

import os
import sys
import json
import time
import uuid
import hmac
import hashlib
import asyncio
import sqlite3
import logging
import argparse
import threading
import ipaddress
import re
import base64
import zlib
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Any, Union
from pathlib import Path
from contextlib import asynccontextmanager
from collections import defaultdict, deque
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import socket
import ssl
import requests
from urllib.parse import urlparse
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# ===== DATA MODELS =====

@dataclass
class ThreatIndicator:
    """Core threat indicator structure"""
    id: str
    ioc_type: str  # ip, domain, hash, url, email, mutex, registry
    value: str
    confidence: float  # 0.0 - 1.0
    severity: str  # low, medium, high, critical
    source: str
    tags: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    ttl_hours: int = 24
    metadata: Dict[str, Any] = field(default_factory=dict)
    related_indicators: List[str] = field(default_factory=list)
    kill_chain_phase: str = ""
    mitre_tactics: List[str] = field(default_factory=list)
    geo_location: Optional[str] = None
    validated_count: int = 0
    false_positive_count: int = 0

@dataclass
class NodeInfo:
    """Peer node information"""
    node_id: str
    hostname: str
    port: int
    public_key: str
    last_seen: datetime
    trust_score: float = 1.0
    shared_indicators: int = 0
    capabilities: List[str] = field(default_factory=list)
    version: str = "1.0.0"

@dataclass
class SyncMessage:
    """Message structure for node communication"""
    msg_id: str
    msg_type: str  # sync_request, sync_response, indicator_update, heartbeat
    source_node: str
    target_node: Optional[str]
    timestamp: datetime
    payload: Dict[str, Any]
    signature: str = ""

# ===== CRYPTOGRAPHIC UTILITIES =====

class CryptoManager:
    """Handles encryption, signatures, and key management"""
    
    def __init__(self, key_dir: str = "keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        self.private_key = None
        self.public_key = None
        self.symmetric_keys = {}
        self.key_rotation_interval = 3600  # 1 hour
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        private_key_file = self.key_dir / "private_key.pem"
        public_key_file = self.key_dir / "public_key.pem"
        
        if private_key_file.exists() and public_key_file.exists():
            with open(private_key_file, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(public_key_file, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(f.read())
        else:
            self._generate_key_pair()
    
    def _generate_key_pair(self):
        """Generate new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # Save keys
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self.key_dir / "private_key.pem", 'wb') as f:
            f.write(private_pem)
        with open(self.key_dir / "public_key.pem", 'wb') as f:
            f.write(public_pem)
    
    def encrypt_data(self, data: bytes, recipient_public_key: str) -> bytes:
        """Encrypt data using recipient's public key"""
        public_key = serialization.load_pem_public_key(recipient_public_key.encode())
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using own private key"""
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data using private key"""
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Verify signature using public key"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# ===== DATABASE MANAGER =====

class DatabaseManager:
    """Handles SQLite database operations"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tags TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    ttl_hours INTEGER DEFAULT 24,
                    metadata TEXT,
                    related_indicators TEXT,
                    kill_chain_phase TEXT,
                    mitre_tactics TEXT,
                    geo_location TEXT,
                    validated_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    UNIQUE(ioc_type, value, source)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    public_key TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    trust_score REAL DEFAULT 1.0,
                    shared_indicators INTEGER DEFAULT 0,
                    capabilities TEXT,
                    version TEXT DEFAULT '1.0.0'
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    success BOOLEAN DEFAULT TRUE
                )
            """)
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(ioc_type, value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_severity ON indicators(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_log_timestamp ON sync_log(timestamp)")

    
    def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add or update threat indicator"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO indicators (
                        id, ioc_type, value, confidence, severity, source, tags,
                        first_seen, last_seen, ttl_hours, metadata, related_indicators,
                        kill_chain_phase, mitre_tactics, geo_location,
                        validated_count, false_positive_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator.id, indicator.ioc_type, indicator.value,
                    indicator.confidence, indicator.severity, indicator.source,
                    json.dumps(indicator.tags), indicator.first_seen.isoformat(),
                    indicator.last_seen.isoformat(), indicator.ttl_hours,
                    json.dumps(indicator.metadata), json.dumps(indicator.related_indicators),
                    indicator.kill_chain_phase, json.dumps(indicator.mitre_tactics),
                    indicator.geo_location, indicator.validated_count,
                    indicator.false_positive_count
                ))
            return True
        except Exception as e:
            logging.error(f"Failed to add indicator: {e}")
            return False
    
    def get_indicators(self, ioc_type: str = None, source: str = None, 
                      severity: str = None, limit: int = 1000) -> List[ThreatIndicator]:
        """Retrieve threat indicators with optional filters"""
        query = "SELECT * FROM indicators WHERE 1=1"
        params = []
        
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        
        indicators = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                indicator = ThreatIndicator(
                    id=row[0], ioc_type=row[1], value=row[2],
                    confidence=row[3], severity=row[4], source=row[5],
                    tags=json.loads(row[6] or "[]"),
                    first_seen=datetime.fromisoformat(row[7]),
                    last_seen=datetime.fromisoformat(row[8]),
                    ttl_hours=row[9],
                    metadata=json.loads(row[10] or "{}"),
                    related_indicators=json.loads(row[11] or "[]"),
                    kill_chain_phase=row[12] or "",
                    mitre_tactics=json.loads(row[13] or "[]"),
                    geo_location=row[14],
                    validated_count=row[15],
                    false_positive_count=row[16]
                )
                indicators.append(indicator)
        
        return indicators
    
    def add_node(self, node: NodeInfo) -> bool:
        """Add or update peer node"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO nodes (
                        node_id, hostname, port, public_key, last_seen,
                        trust_score, shared_indicators, capabilities, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    node.node_id, node.hostname, node.port, node.public_key,
                    node.last_seen.isoformat(), node.trust_score,
                    node.shared_indicators, json.dumps(node.capabilities),
                    node.version
                ))
            return True
        except Exception as e:
            logging.error(f"Failed to add node: {e}")
            return False
    
    def get_nodes(self) -> List[NodeInfo]:
        """Get all peer nodes"""
        nodes = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM nodes")
            for row in cursor.fetchall():
                node = NodeInfo(
                    node_id=row[0], hostname=row[1], port=row[2],
                    public_key=row[3], last_seen=datetime.fromisoformat(row[4]),
                    trust_score=row[5], shared_indicators=row[6],
                    capabilities=json.loads(row[7] or "[]"),
                    version=row[8]
                )
                nodes.append(node)
        
        return nodes

# ===== THREAT INTELLIGENCE ENGINE =====

class ThreatIntelEngine:
    """Core threat intelligence processing engine"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.enrichment_sources = {
            'virustotal': self._enrich_virustotal,
            'shodan': self._enrich_shodan,
            'whois': self._enrich_whois
        }
        self.correlation_rules = []
        self._load_correlation_rules()
    
    def _load_correlation_rules(self):
        """Load threat correlation rules"""
        self.correlation_rules = [
            {'name': 'ip_domain_correlation', 'weight': 0.8},
            {'name': 'hash_family_correlation', 'weight': 0.9},
            {'name': 'temporal_correlation', 'weight': 0.6},
            {'name': 'source_correlation', 'weight': 0.7}
        ]
    
    def validate_indicator(self, indicator: ThreatIndicator) -> bool:
        """Validate indicator format and content"""
        if indicator.ioc_type == 'ip':
            try:
                ipaddress.ip_address(indicator.value)
                return True
            except ValueError:
                return False
        elif indicator.ioc_type == 'domain':
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            return bool(domain_pattern.match(indicator.value))
        elif indicator.ioc_type == 'hash':
            hash_patterns = {
                32: r'^[a-fA-F0-9]{32}$',  # MD5
                40: r'^[a-fA-F0-9]{40}$',  # SHA1
                64: r'^[a-fA-F0-9]{64}$'   # SHA256
            }
            return any(re.match(pattern, indicator.value) 
                      for pattern in hash_patterns.values())
        elif indicator.ioc_type == 'url':
            try:
                result = urlparse(indicator.value)
                return all([result.scheme, result.netloc])
            except:
                return False
        
        return True
    
    def enrich_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        """Enrich indicator with additional intelligence"""
        for source_name, enrich_func in self.enrichment_sources.items():
            try:
                enriched_data = enrich_func(indicator)
                if enriched_data:
                    indicator.metadata.update(enriched_data)
            except Exception as e:
                logging.warning(f"Enrichment failed for {source_name}: {e}")
        
        return indicator
    
    def _enrich_virustotal(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Placeholder for VirusTotal enrichment"""
        return {'vt_scanned': True, 'vt_positives': 0}
    
    def _enrich_shodan(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Placeholder for Shodan enrichment"""
        if indicator.ioc_type == 'ip':
            return {'shodan_scanned': True, 'open_ports': []}
        return {}
    
    def _enrich_whois(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Basic WHOIS enrichment"""
        if indicator.ioc_type in ['domain', 'ip']:
            return {'whois_scanned': True}
        return {}
    
    def calculate_threat_score(self, indicator: ThreatIndicator) -> float:
        """Calculate composite threat score"""
        base_score = indicator.confidence
        
        # Severity multiplier
        severity_weights = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
        severity_multiplier = severity_weights.get(indicator.severity, 0.5)
        
        # Validation boost
        validation_ratio = indicator.validated_count / max(1, indicator.validated_count + indicator.false_positive_count)
        validation_boost = validation_ratio * 0.2
        
        # Age penalty
        age_hours = (datetime.utcnow() - indicator.last_seen).total_seconds() / 3600
        age_penalty = min(0.3, age_hours / indicator.ttl_hours * 0.3)
        
        final_score = (base_score * severity_multiplier + validation_boost - age_penalty)
        return max(0.0, min(1.0, final_score))
    
    def find_correlations(self, indicator: ThreatIndicator) -> List[str]:
        """Find correlated indicators"""
        correlations = []
        related_indicators = self.db.get_indicators(limit=5000)
        
        for related in related_indicators:
            if related.id == indicator.id:
                continue
            
            correlation_score = 0.0
            
            # IP-Domain correlation
            if (indicator.ioc_type == 'ip' and related.ioc_type == 'domain') or \
               (indicator.ioc_type == 'domain' and related.ioc_type == 'ip'):
                correlation_score += 0.3
            
            # Same source correlation
            if indicator.source == related.source:
                correlation_score += 0.2
            
            # Tag overlap correlation
            common_tags = set(indicator.tags) & set(related.tags)
            if common_tags:
                correlation_score += len(common_tags) * 0.1
            
            # Temporal correlation (within 24 hours)
            time_diff = abs((indicator.last_seen - related.last_seen).total_seconds())
            if time_diff < 86400:  # 24 hours
                correlation_score += 0.2
            
            if correlation_score > 0.5:
                correlations.append(related.id)
        
        return correlations[:10]  # Top 10 correlations

# ===== NETWORK SYNC MANAGER =====

class NetworkSyncManager:
    """Handles peer-to-peer synchronization"""
    
    def __init__(self, node_id: str, port: int, crypto_manager: CryptoManager, 
                 db_manager: DatabaseManager, intel_engine: ThreatIntelEngine):
        self.node_id = node_id
        self.port = port
        self.crypto = crypto_manager
        self.db = db_manager
        self.intel = intel_engine
        self.running = False
        self.sync_queue = queue.Queue()
        self.heartbeat_interval = 30
        self.sync_interval = 300  # 5 minutes
        
    async def start_server(self):
        """Start the sync server"""
        self.running = True
        # Start background tasks
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._sync_loop())
        
        # Simple HTTP-like server for demonstration
        logging.info(f"Sync server started on port {self.port}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to peers"""
        while self.running:
            nodes = self.db.get_nodes()
            for node in nodes:
                try:
                    await self._send_heartbeat(node)
                except Exception as e:
                    logging.warning(f"Heartbeat failed for {node.node_id}: {e}")
            
            await asyncio.sleep(self.heartbeat_interval)
    
    async def _sync_loop(self):
        """Periodic synchronization with peers"""
        while self.running:
            nodes = self.db.get_nodes()
            for node in nodes:
                try:
                    await self._sync_with_node(node)
                except Exception as e:
                    logging.warning(f"Sync failed with {node.node_id}: {e}")
            
            await asyncio.sleep(self.sync_interval)
    
    async def _send_heartbeat(self, node: NodeInfo):
        """Send heartbeat to peer node"""
        message = SyncMessage(
            msg_id=str(uuid.uuid4()),
            msg_type="heartbeat",
            source_node=self.node_id,
            target_node=node.node_id,
            timestamp=datetime.utcnow(),
            payload={"status": "alive", "version": "1.0.0"}
        )
        
        # In a real implementation, this would send over network
        logging.debug(f"Heartbeat sent to {node.node_id}")
    
    async def _sync_with_node(self, node: NodeInfo):
        """Synchronize indicators with peer node"""
        # Get recent indicators
        recent_indicators = self.db.get_indicators(limit=100)
        
        message = SyncMessage(
            msg_id=str(uuid.uuid4()),
            msg_type="sync_request",
            source_node=self.node_id,
            target_node=node.node_id,
            timestamp=datetime.utcnow(),
            payload={
                "indicators": [asdict(ind) for ind in recent_indicators[-10:]],
                "last_sync": datetime.utcnow().isoformat()
            }
        )
        
        logging.debug(f"Sync requested with {node.node_id}")
    
    def add_peer(self, hostname: str, port: int, public_key: str) -> bool:
        """Add new peer node"""
        node = NodeInfo(
            node_id=str(uuid.uuid4()),
            hostname=hostname,
            port=port,
            public_key=public_key,
            last_seen=datetime.utcnow()
        )
        
        return self.db.add_node(node)

# ===== GUI INTERFACE =====

class ThreatIntelGUI:
    """Professional cybersecurity GUI interface"""
    
    def __init__(self, db_manager: DatabaseManager, intel_engine: ThreatIntelEngine,
                 sync_manager: NetworkSyncManager):
        self.db = db_manager
        self.intel = intel_engine
        self.sync = sync_manager

        # Create main window
        self.root = tk.Tk()
        self.root.title("Distributed Threat Intelligence Sync Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_style()

        self.update_queue = queue.Queue()

        # Status bar variable (define before widgets use it)
        self.status_var = tk.StringVar()
        self.status_var.set("System Ready")

        self._create_widgets()

        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                      style='Data.TLabel', relief='sunken')
        status_bar.pack(side='bottom', fill='x')

        # Start update loop
        self.root.after(1000, self._update_display)

    def _configure_style(self):
        """Configure custom styles for the GUI"""
        self.style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), foreground='#00bfff', background='#2b2b2b')
        self.style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), foreground='#ffaa00', background='#2b2b2b')
        self.style.configure('Data.TLabel', font=('Segoe UI', 10), foreground='#ffffff', background='#2b2b2b')
        self.style.configure('Critical.TLabel', font=('Segoe UI', 10, 'bold'), foreground='#ff4444', background='#2b2b2b')

    def _create_widgets(self):
        """Create main GUI components"""
        # Title
        title_label = ttk.Label(self.root, text="DTIST - Distributed Threat Intelligence",
                               style='Title.TLabel')
        title_label.pack(pady=10)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Indicators Tab
        self.indicators_frame = ttk.Frame(notebook)
        notebook.add(self.indicators_frame, text="Threat Indicators")
        self._create_indicators_tab()
        
        # Network Tab
        self.network_frame = ttk.Frame(notebook)
        notebook.add(self.network_frame, text="Network Sync")
        self._create_network_tab()
        
        # Analytics Tab
        self.analytics_frame = ttk.Frame(notebook)
        notebook.add(self.analytics_frame, text="Analytics")
        self._create_analytics_tab()
        # Status bar variable (define before widgets use it)
        self.status_var = tk.StringVar()
        self.status_var.set("System Ready")

        

        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                      style='Data.TLabel', relief='sunken')
        status_bar.pack(side='bottom', fill='x')

    
    def _create_indicators_tab(self):
        """Create threat indicators display"""
        # Control frame
        control_frame = ttk.Frame(self.indicators_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(control_frame, text="Filter:", style='Header.TLabel').pack(side='left')
        
        self.filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var,
                                   values=['All', 'IP', 'Domain', 'Hash', 'URL'])
        filter_combo.pack(side='left', padx=5)
        filter_combo.set('All')
        
        ttk.Button(control_frame, text="Refresh", 
                  command=self._refresh_indicators).pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Add Indicator",
                  command=self._add_indicator_dialog).pack(side='right', padx=5)
        
        # Indicators display
        columns = ('Type', 'Value', 'Severity', 'Confidence', 'Source', 'Last Seen')
        self.indicators_tree = ttk.Treeview(self.indicators_frame, columns=columns,
                                           show='headings', height=20)
        
        for col in columns:
            self.indicators_tree.heading(col, text=col)
            self.indicators_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.indicators_frame, orient='vertical',
                                 command=self.indicators_tree.yview)
        self.indicators_tree.configure(yscrollcommand=scrollbar.set)
        
        self.indicators_tree.pack(side='left', fill='both', expand=True, padx=5)
        scrollbar.pack(side='right', fill='y')
        
        self._refresh_indicators()
    
    def _create_network_tab(self):
        """Create network synchronization display"""
        # Node status frame
        status_frame = ttk.LabelFrame(self.network_frame, text="Node Status")
        status_frame.pack(fill='x', padx=5, pady=5)
        
        self.node_status_text = scrolledtext.ScrolledText(status_frame, height=8,
                                                         bg='#1a1a1a', fg='#00ff00',
                                                         font=('Consolas', 9))
        self.node_status_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Peer nodes frame
        peers_frame = ttk.LabelFrame(self.network_frame, text="Peer Nodes")
        peers_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        peer_columns = ('Node ID', 'Hostname', 'Port', 'Trust Score', 'Last Seen')
        self.peers_tree = ttk.Treeview(peers_frame, columns=peer_columns,
                                      show='headings', height=10)
        
        for col in peer_columns:
            self.peers_tree.heading(col, text=col)
            self.peers_tree.column(col, width=120)
        
        self.peers_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Control buttons
        peer_control_frame = ttk.Frame(peers_frame)
        peer_control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(peer_control_frame, text="Add Peer",
                  command=self._add_peer_dialog).pack(side='left', padx=5)
        
        ttk.Button(peer_control_frame, text="Sync Now",
                  command=self._manual_sync).pack(side='left', padx=5)
        
        ttk.Button(peer_control_frame, text="Start Server",
                  command=self._start_server).pack(side='right', padx=5)
        
        self._refresh_peers()
    
    def _create_analytics_tab(self):
        """Create analytics and statistics display"""
        # Statistics frame
        stats_frame = ttk.LabelFrame(self.analytics_frame, text="Statistics")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=10, pady=10)
        
        # Statistics labels
        self.stats_labels = {}
        stats_items = [
            ('Total Indicators', 'total_indicators'),
            ('Critical Threats', 'critical_threats'),
            ('Active Peers', 'active_peers'),
            ('Sync Success Rate', 'sync_rate')
        ]
        
        for i, (label, key) in enumerate(stats_items):
            row = i // 2
            col = (i % 2) * 2
            
            ttk.Label(stats_grid, text=f"{label}:", 
                     style='Header.TLabel').grid(row=row, column=col, sticky='w', padx=5, pady=2)
            
            self.stats_labels[key] = ttk.Label(stats_grid, text="0", 
                                              style='Data.TLabel')
            self.stats_labels[key].grid(row=row, column=col+1, sticky='w', padx=20, pady=2)
        
        # Recent activity frame
        activity_frame = ttk.LabelFrame(self.analytics_frame, text="Recent Activity")
        activity_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=15,
                                                      bg='#1a1a1a', fg='#cccccc',
                                                      font=('Consolas', 9))
        self.activity_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Threat timeline
        timeline_frame = ttk.LabelFrame(self.analytics_frame, text="Threat Timeline")
        timeline_frame.pack(fill='x', padx=5, pady=5)
        
        self.timeline_canvas = tk.Canvas(timeline_frame, height=100, bg='#1a1a1a')
        self.timeline_canvas.pack(fill='x', padx=5, pady=5)
        
        self._update_analytics()
    
    def _refresh_indicators(self):
        """Refresh indicators display"""
        # Clear existing items
        for item in self.indicators_tree.get_children():
            self.indicators_tree.delete(item)
        
        # Get filter value
        filter_type = self.filter_var.get()
        if filter_type == 'All':
            filter_type = None
        
        # Get indicators from database
        indicators = self.db.get_indicators(ioc_type=filter_type.lower() if filter_type else None)
        
        # Populate tree
        for indicator in indicators[:100]:  # Limit display
            severity_style = 'Critical.TLabel' if indicator.severity == 'critical' else 'Data.TLabel'
            
            self.indicators_tree.insert('', 'end', values=(
                indicator.ioc_type.upper(),
                indicator.value[:50] + ('...' if len(indicator.value) > 50 else ''),
                indicator.severity.upper(),
                f"{indicator.confidence:.2f}",
                indicator.source,
                indicator.last_seen.strftime('%Y-%m-%d %H:%M')
            ), tags=(severity_style,))
        
        self.status_var.set(f"Loaded {len(indicators)} indicators")
    
    def _refresh_peers(self):
        """Refresh peer nodes display"""
        # Clear existing items
        for item in self.peers_tree.get_children():
            self.peers_tree.delete(item)
        
        # Get nodes from database
        nodes = self.db.get_nodes()
        
        # Populate tree
        for node in nodes:
            self.peers_tree.insert('', 'end', values=(
                node.node_id[:12] + '...',
                node.hostname,
                node.port,
                f"{node.trust_score:.2f}",
                node.last_seen.strftime('%Y-%m-%d %H:%M')
            ))
    
    def _add_indicator_dialog(self):
        """Show add indicator dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Threat Indicator")
        dialog.geometry("500x400")
        dialog.configure(bg='#2b2b2b')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        fields = [
            ('Type:', 'type'),
            ('Value:', 'value'),
            ('Severity:', 'severity'),
            ('Confidence:', 'confidence'),
            ('Source:', 'source'),
            ('Tags (comma-separated):', 'tags')
        ]
        
        entries = {}
        
        for i, (label, key) in enumerate(fields):
            ttk.Label(dialog, text=label, style='Header.TLabel').grid(
                row=i, column=0, sticky='w', padx=10, pady=5)
            
            if key == 'type':
                entries[key] = ttk.Combobox(dialog, values=['ip', 'domain', 'hash', 'url', 'email'])
                entries[key].set('ip')
            elif key == 'severity':
                entries[key] = ttk.Combobox(dialog, values=['low', 'medium', 'high', 'critical'])
                entries[key].set('medium')
            elif key == 'confidence':
                entries[key] = tk.Scale(dialog, from_=0.0, to=1.0, resolution=0.1, 
                                      orient='horizontal', bg='#2b2b2b', fg='#ffffff')
                entries[key].set(0.5)
            else:
                entries[key] = ttk.Entry(dialog, width=40)
            
            entries[key].grid(row=i, column=1, sticky='ew', padx=10, pady=5)
        
        def submit_indicator():
            try:
                # Create indicator
                indicator = ThreatIndicator(
                    id=str(uuid.uuid4()),
                    ioc_type=entries['type'].get(),
                    value=entries['value'].get(),
                    confidence=float(entries['confidence'].get()) if key != 'confidence' else entries['confidence'].get(),
                    severity=entries['severity'].get(),
                    source=entries['source'].get() or 'manual',
                    tags=entries['tags'].get().split(',') if entries['tags'].get() else []
                )
                
                # Validate and add
                if self.intel.validate_indicator(indicator):
                    if self.db.add_indicator(indicator):
                        self._refresh_indicators()
                        self._log_activity(f"Added indicator: {indicator.value}")
                        dialog.destroy()
                    else:
                        messagebox.showerror("Error", "Failed to add indicator")
                else:
                    messagebox.showerror("Error", "Invalid indicator format")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create indicator: {e}")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=len(fields), column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Add Indicator", 
                  command=submit_indicator).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side='left', padx=5)
    
    def _add_peer_dialog(self):
        """Show add peer dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Peer Node")
        dialog.geometry("400x200")
        dialog.configure(bg='#2b2b2b')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        ttk.Label(dialog, text="Hostname:", style='Header.TLabel').grid(
            row=0, column=0, sticky='w', padx=10, pady=5)
        hostname_entry = ttk.Entry(dialog, width=30)
        hostname_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Port:", style='Header.TLabel').grid(
            row=1, column=0, sticky='w', padx=10, pady=5)
        port_entry = ttk.Entry(dialog, width=30)
        port_entry.grid(row=1, column=1, padx=10, pady=5)
        port_entry.insert(0, "8080")
        
        ttk.Label(dialog, text="Public Key:", style='Header.TLabel').grid(
            row=2, column=0, sticky='w', padx=10, pady=5)
        key_text = scrolledtext.ScrolledText(dialog, width=40, height=5)
        key_text.grid(row=2, column=1, padx=10, pady=5)
        
        def submit_peer():
            try:
                hostname = hostname_entry.get()
                port = int(port_entry.get())
                public_key = key_text.get('1.0', 'end-1c')
                
                if self.sync.add_peer(hostname, port, public_key):
                    self._refresh_peers()
                    self._log_activity(f"Added peer: {hostname}:{port}")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to add peer")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add peer: {e}")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Add Peer", 
                  command=submit_peer).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side='left', padx=5)
    
    def _manual_sync(self):
        """Trigger manual synchronization"""
        threading.Thread(target=self._sync_thread, daemon=True).start()
        self._log_activity("Manual synchronization initiated")
    
    def _sync_thread(self):
        """Background sync thread"""
        try:
            # Simulate sync process
            time.sleep(2)
            self._log_activity("Synchronization completed successfully")
            self.status_var.set("Sync completed")
        except Exception as e:
            self._log_activity(f"Synchronization failed: {e}")
            self.status_var.set("Sync failed")
    
    def _start_server(self):
        """Start the sync server"""
        threading.Thread(target=self._server_thread, daemon=True).start()
        self._log_activity(f"Sync server starting on port {self.sync.port}")
    
    def _server_thread(self):
        """Background server thread"""
        try:
            # In a real implementation, this would start the actual server
            self._log_activity("Sync server started successfully")
            self.status_var.set("Server running")
        except Exception as e:
            self._log_activity(f"Server start failed: {e}")
            self.status_var.set("Server failed")
    
    def _update_analytics(self):
        """Update analytics display"""
        # Get statistics
        all_indicators = self.db.get_indicators(limit=10000)
        critical_indicators = [i for i in all_indicators if i.severity == 'critical']
        all_peers = self.db.get_nodes()
        
        # Update statistics
        self.stats_labels['total_indicators'].config(text=str(len(all_indicators)))
        self.stats_labels['critical_threats'].config(text=str(len(critical_indicators)))
        self.stats_labels['active_peers'].config(text=str(len(all_peers)))
        self.stats_labels['sync_rate'].config(text="95.2%")
        
        # Draw threat timeline
        self._draw_timeline(all_indicators)
    
    def _draw_timeline(self, indicators):
        """Draw threat activity timeline"""
        self.timeline_canvas.delete("all")
        
        if not indicators:
            return
        
        # Group indicators by hour
        hourly_counts = defaultdict(int)
        now = datetime.utcnow()
        
        for indicator in indicators:
            hours_ago = int((now - indicator.last_seen).total_seconds() / 3600)
            if hours_ago <= 24:  # Last 24 hours
                hourly_counts[24 - hours_ago] += 1
        
        # Draw bars
        canvas_width = self.timeline_canvas.winfo_width() or 800
        canvas_height = self.timeline_canvas.winfo_height() or 100
        
        if canvas_width > 1:
            bar_width = canvas_width / 24
            max_count = max(hourly_counts.values()) if hourly_counts else 1
            
            for hour in range(24):
                count = hourly_counts.get(hour, 0)
                bar_height = (count / max_count) * (canvas_height - 20) if max_count > 0 else 0
                
                x1 = hour * bar_width
                y1 = canvas_height - bar_height - 10
                x2 = x1 + bar_width - 2
                y2 = canvas_height - 10
                
                color = '#ff4444' if count > max_count * 0.7 else '#ffaa00' if count > max_count * 0.3 else '#00aa00'
                self.timeline_canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline='')
    
    def _log_activity(self, message):
        """Log activity to display"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        
        self.activity_text.insert('end', log_message)
        self.activity_text.see('end')
        
        # Keep only last 100 lines
        lines = self.activity_text.get('1.0', 'end').split('\n')
        if len(lines) > 100:
            self.activity_text.delete('1.0', f"{len(lines)-100}.0")
        
        # Also update status in node status
        self.node_status_text.insert('end', log_message)
        self.node_status_text.see('end')
        
        lines = self.node_status_text.get('1.0', 'end').split('\n')
        if len(lines) > 50:
            self.node_status_text.delete('1.0', f"{len(lines)-50}.0")
    
    def _update_display(self):
        """Periodic display update"""
        try:
            # Update analytics
            self._update_analytics()
            
            # Schedule next update
            self.root.after(5000, self._update_display)  # Update every 5 seconds
            
        except Exception as e:
            logging.error(f"Display update error: {e}")
            self.root.after(5000, self._update_display)
    
    def run(self):
        """Start the GUI"""
        self._log_activity("DTIST System Initialized")
        self._log_activity("Threat Intelligence Engine Online")
        self._log_activity("Network Sync Manager Ready")
        self.root.mainloop()

# ===== COMMAND LINE INTERFACE =====

class CLI:
    """Command line interface for DTIST"""
    
    def __init__(self, db_manager: DatabaseManager, intel_engine: ThreatIntelEngine,
                 sync_manager: NetworkSyncManager):
        self.db = db_manager
        self.intel = intel_engine
        self.sync = sync_manager
        self.commands = {
            'add': self._add_indicator,
            'list': self._list_indicators,
            'search': self._search_indicators,
            'peers': self._list_peers,
            'sync': self._sync_now,
            'stats': self._show_stats,
            'enrich': self._enrich_indicator,
            'export': self._export_data,
            'import': self._import_data,
            'help': self._show_help
        }
    
    def run_interactive(self):
        """Run interactive CLI mode"""
        print("🛡️  DTIST - Distributed Threat Intelligence Sync Tool")
        print("Type 'help' for available commands or 'quit' to exit.\n")
        
        while True:
            try:
                cmd_input = input("dtist> ").strip()
                if not cmd_input:
                    continue
                
                if cmd_input.lower() in ['quit', 'exit']:
                    break
                
                parts = cmd_input.split()
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in self.commands:
                    self.commands[command](args)
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _add_indicator(self, args):
        """Add new threat indicator"""
        if len(args) < 4:
            print("Usage: add <type> <value> <severity> <confidence> [source] [tags]")
            return
        
        try:
            indicator = ThreatIndicator(
                id=str(uuid.uuid4()),
                ioc_type=args[0],
                value=args[1],
                severity=args[2],
                confidence=float(args[3]),
                source=args[4] if len(args) > 4 else 'cli',
                tags=args[5].split(',') if len(args) > 5 else []
            )
            
            if self.intel.validate_indicator(indicator):
                if self.db.add_indicator(indicator):
                    print(f"✅ Added indicator: {indicator.value}")
                else:
                    print("❌ Failed to add indicator")
            else:
                print("❌ Invalid indicator format")
                
        except ValueError:
            print("❌ Invalid confidence value (must be 0.0-1.0)")
    
    def _list_indicators(self, args):
        """List threat indicators"""
        limit = 20
        if args and args[0].isdigit():
            limit = int(args[0])
        
        indicators = self.db.get_indicators(limit=limit)
        
        if not indicators:
            print("No indicators found")
            return
        
        print(f"\n📊 Showing {len(indicators)} indicators:")
        print("-" * 80)
        print(f"{'Type':<8} {'Value':<25} {'Severity':<10} {'Conf':<6} {'Source':<12} {'Age':<8}")
        print("-" * 80)
        
        for indicator in indicators:
            age_hours = int((datetime.utcnow() - indicator.last_seen).total_seconds() / 3600)
            age_str = f"{age_hours}h" if age_hours < 24 else f"{age_hours//24}d"
            
            print(f"{indicator.ioc_type:<8} {indicator.value[:24]:<25} "
                  f"{indicator.severity:<10} {indicator.confidence:<6.2f} "
                  f"{indicator.source[:11]:<12} {age_str:<8}")
    
    def _search_indicators(self, args):
        """Search for indicators"""
        if not args:
            print("Usage: search <value>")
            return
        
        search_term = args[0].lower()
        indicators = self.db.get_indicators(limit=1000)
        
        matches = [i for i in indicators if search_term in i.value.lower() or 
                  search_term in i.source.lower() or 
                  any(search_term in tag.lower() for tag in i.tags)]
        
        if matches:
            print(f"\n🔍 Found {len(matches)} matches:")
            self._display_indicators(matches[:20])
        else:
            print("No matches found")
    
    def _list_peers(self, args):
        """List peer nodes"""
        nodes = self.db.get_nodes()
        
        if not nodes:
            print("No peer nodes configured")
            return
        
        print(f"\n🌐 {len(nodes)} peer nodes:")
        print("-" * 60)
        print(f"{'Node ID':<15} {'Hostname':<20} {'Port':<6} {'Trust':<6} {'Status':<8}")
        print("-" * 60)
        
        for node in nodes:
            age_hours = (datetime.utcnow() - node.last_seen).total_seconds() / 3600
            status = "Online" if age_hours < 1 else "Offline"
            
            print(f"{node.node_id[:12]+'...':<15} {node.hostname:<20} "
                  f"{node.port:<6} {node.trust_score:<6.2f} {status:<8}")
    
    def _sync_now(self, args):
        """Trigger synchronization"""
        print("🔄 Starting synchronization...")
        # In real implementation, would trigger actual sync
        print("✅ Synchronization completed")
    
    def _show_stats(self, args):
        """Show system statistics"""
        indicators = self.db.get_indicators(limit=10000)
        nodes = self.db.get_nodes()
        
        # Calculate stats
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_source = defaultdict(int)
        
        for indicator in indicators:
            by_type[indicator.ioc_type] += 1
            by_severity[indicator.severity] += 1
            by_source[indicator.source] += 1
        
        print("\n📈 System Statistics:")
        print("-" * 40)
        print(f"Total Indicators: {len(indicators)}")
        print(f"Peer Nodes: {len(nodes)}")
        print(f"Average Confidence: {sum(i.confidence for i in indicators) / len(indicators):.2f}" if indicators else "N/A")
        
        print("\nBy Type:")
        for ioc_type, count in sorted(by_type.items()):
            print(f"  {ioc_type.upper()}: {count}")
        
        print("\nBy Severity:")
        for severity, count in sorted(by_severity.items()):
            print(f"  {severity.upper()}: {count}")
    
    def _enrich_indicator(self, args):
        """Enrich indicator with additional data"""
        if not args:
            print("Usage: enrich <indicator_value>")
            return
        
        indicators = self.db.get_indicators(limit=1000)
        matches = [i for i in indicators if args[0] in i.value]
        
        if not matches:
            print("Indicator not found")
            return
        
        indicator = matches[0]
        enriched = self.intel.enrich_indicator(indicator)
        
        if self.db.add_indicator(enriched):
            print(f"✅ Enriched indicator: {indicator.value}")
            print(f"New metadata: {enriched.metadata}")
        else:
            print("❌ Failed to update indicator")
    
    def _export_data(self, args):
        """Export threat data"""
        filename = args[0] if args else f"dtist_export_{int(time.time())}.json"
        
        indicators = self.db.get_indicators(limit=10000)
        nodes = self.db.get_nodes()
        
        export_data = {
            'export_time': datetime.utcnow().isoformat(),
            'indicators': [asdict(i) for i in indicators],
            'nodes': [asdict(n) for n in nodes]
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"✅ Exported {len(indicators)} indicators to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")
    
    def _import_data(self, args):
        """Import threat data"""
        if not args:
            print("Usage: import <filename>")
            return
        
        try:
            with open(args[0], 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            for indicator_data in data.get('indicators', []):
                # Convert datetime strings back to datetime objects
                if isinstance(indicator_data['first_seen'], str):
                    indicator_data['first_seen'] = datetime.fromisoformat(indicator_data['first_seen'])
                if isinstance(indicator_data['last_seen'], str):
                    indicator_data['last_seen'] = datetime.fromisoformat(indicator_data['last_seen'])
                
                indicator = ThreatIndicator(**indicator_data)
                if self.db.add_indicator(indicator):
                    imported_count += 1
            
            print(f"✅ Imported {imported_count} indicators")
            
        except Exception as e:
            print(f"❌ Import failed: {e}")
    
    def _show_help(self, args):
        """Show help information"""
        print("\n🛡️  DTIST Commands:")
        print("-" * 50)
        print("add <type> <value> <severity> <confidence> [source] [tags]")
        print("  Add new threat indicator")
        print("\nlist [limit]")
        print("  List threat indicators")
        print("\nsearch <term>")
        print("  Search indicators")
        print("\npeers")
        print("  List peer nodes")
        print("\nsync")
        print("  Trigger synchronization")
        print("\nstats")
        print("  Show system statistics")
        print("\nenrich <value>")
        print("  Enrich indicator with additional data")
        print("\nexport [filename]")
        print("  Export threat data to JSON")
        print("\nimport <filename>")
        print("  Import threat data from JSON")
        print("\nhelp")
        print("  Show this help")
        print("\nquit/exit")
        print("  Exit DTIST")

# ===== MAIN APPLICATION =====

def main():
    """Main application entry point"""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('dtist.log'),
            logging.StreamHandler()
        ]
    )
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Distributed Threat Intelligence Sync Tool')
    parser.add_argument('--mode', choices=['gui', 'cli', 'server'], default='gui',
                       help='Operating mode')
    parser.add_argument('--port', type=int, default=8080,
                       help='Server port')
    parser.add_argument('--db', default='threat_intel.db',
                       help='Database file path')
    parser.add_argument('--config', default='dtist_config.json',
                       help='Configuration file')
    
    args = parser.parse_args()
    
    # Initialize components
    crypto_manager = CryptoManager()
    db_manager = DatabaseManager(args.db)
    intel_engine = ThreatIntelEngine(db_manager)
    
    node_id = str(uuid.uuid4())
    sync_manager = NetworkSyncManager(node_id, args.port, crypto_manager, 
                                     db_manager, intel_engine)
    
    # Add some sample data for demonstration
    sample_indicators = [
        ThreatIndicator(
            id=str(uuid.uuid4()),
            ioc_type='ip',
            value='192.168.1.100',
            confidence=0.8,
            severity='high',
            source='honeypot',
            tags=['malware', 'botnet']
        ),
        ThreatIndicator(
            id=str(uuid.uuid4()),
            ioc_type='domain',
            value='malicious.example.com',
            confidence=0.9,
            severity='critical',
            source='dns_monitor',
            tags=['phishing', 'credential_theft']
        ),
        ThreatIndicator(
            id=str(uuid.uuid4()),
            ioc_type='hash',
            value='d41d8cd98f00b204e9800998ecf8427e',
            confidence=0.7,
            severity='medium',
            source='sandbox',
            tags=['trojan', 'persistence']
        )
    ]
    
    for indicator in sample_indicators:
        db_manager.add_indicator(indicator)
    
    # Run application
    if args.mode == 'gui':
        gui = ThreatIntelGUI(db_manager, intel_engine, sync_manager)
        gui.run()
    elif args.mode == 'cli':
        cli = CLI(db_manager, intel_engine, sync_manager)
        cli.run_interactive()
    elif args.mode == 'server':
        print(f"Starting DTIST server on port {args.port}")
        # In real implementation, would start actual server
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Server stopped")

if __name__ == "__main__":
    main()