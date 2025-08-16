#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE Cache Manager

This module provides caching functionality for CVE scan results to avoid
repeated API calls and improve performance.
"""

import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging


class CVECacheManager:
    """Manages caching of CVE scan results"""
    
    def __init__(self, cache_dir: Optional[Path] = None, cache_duration_hours: int = 24):
        self.logger = logging.getLogger(__name__)
        
        # Default cache directory
        if cache_dir is None:
            cache_dir = Path.home() / ".dexray_insight" / "cve_cache"
        
        self.cache_dir = cache_dir
        self.cache_duration_hours = cache_duration_hours
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache file for metadata
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        
        # Initialize metadata
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Could not load cache metadata: {e}")
        
        return {
            "created": datetime.now().isoformat(),
            "entries": {},
            "stats": {
                "hits": 0,
                "misses": 0,
                "total_requests": 0
            }
        }
    
    def _save_metadata(self):
        """Save cache metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Could not save cache metadata: {e}")
    
    def _generate_cache_key(self, library_name: str, version: str, source: str) -> str:
        """Generate cache key for library/version/source combination"""
        key_data = f"{library_name}:{version}:{source}".lower()
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get cache file path for a given key"""
        return self.cache_dir / f"{cache_key}.json"
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid"""
        if cache_key not in self.metadata["entries"]:
            return False
        
        entry = self.metadata["entries"][cache_key]
        cached_time = datetime.fromisoformat(entry["timestamp"])
        expiry_time = cached_time + timedelta(hours=self.cache_duration_hours)
        
        return datetime.now() < expiry_time
    
    def get_cached_result(self, library_name: str, version: str, source: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached CVE results for a library/version/source combination.
        
        Args:
            library_name: Name of the library
            version: Version of the library  
            source: CVE data source (e.g., "osv", "nvd")
            
        Returns:
            Cached CVE results or None if not cached or expired
        """
        cache_key = self._generate_cache_key(library_name, version, source)
        
        self.metadata["stats"]["total_requests"] += 1
        
        if not self._is_cache_valid(cache_key):
            self.metadata["stats"]["misses"] += 1
            self._save_metadata()
            return None
        
        cache_file = self._get_cache_file_path(cache_key)
        if not cache_file.exists():
            self.metadata["stats"]["misses"] += 1
            self._save_metadata()
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            self.metadata["stats"]["hits"] += 1
            self._save_metadata()
            
            self.logger.debug(f"Cache hit for {library_name}:{version}:{source}")
            return data.get("vulnerabilities", [])
            
        except Exception as e:
            self.logger.warning(f"Could not load cache file {cache_file}: {e}")
            self.metadata["stats"]["misses"] += 1
            self._save_metadata()
            return None
    
    def cache_result(self, library_name: str, version: str, source: str, 
                    vulnerabilities: List[Dict[str, Any]]):
        """
        Cache CVE results for a library/version/source combination.
        
        Args:
            library_name: Name of the library
            version: Version of the library
            source: CVE data source
            vulnerabilities: List of vulnerability dictionaries
        """
        cache_key = self._generate_cache_key(library_name, version, source)
        cache_file = self._get_cache_file_path(cache_key)
        
        cache_data = {
            "library_name": library_name,
            "version": version,
            "source": source,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update metadata
            self.metadata["entries"][cache_key] = {
                "timestamp": cache_data["timestamp"],
                "library_name": library_name,
                "version": version,
                "source": source,
                "vulnerability_count": len(vulnerabilities)
            }
            self._save_metadata()
            
            self.logger.debug(f"Cached {len(vulnerabilities)} vulnerabilities for {library_name}:{version}:{source}")
            
        except Exception as e:
            self.logger.warning(f"Could not cache result: {e}")
    
    def clear_cache(self, older_than_hours: Optional[int] = None):
        """
        Clear cache entries.
        
        Args:
            older_than_hours: Only clear entries older than this many hours.
                             If None, clear all entries.
        """
        cleared_count = 0
        
        if older_than_hours is None:
            # Clear all cache files
            for cache_file in self.cache_dir.glob("*.json"):
                if cache_file.name != "cache_metadata.json":
                    try:
                        cache_file.unlink()
                        cleared_count += 1
                    except Exception as e:
                        self.logger.warning(f"Could not delete cache file {cache_file}: {e}")
            
            # Clear metadata entries
            self.metadata["entries"] = {}
        else:
            # Clear only old entries
            cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
            entries_to_remove = []
            
            for cache_key, entry in self.metadata["entries"].items():
                entry_time = datetime.fromisoformat(entry["timestamp"])
                if entry_time < cutoff_time:
                    cache_file = self._get_cache_file_path(cache_key)
                    try:
                        if cache_file.exists():
                            cache_file.unlink()
                        entries_to_remove.append(cache_key)
                        cleared_count += 1
                    except Exception as e:
                        self.logger.warning(f"Could not delete cache file {cache_file}: {e}")
            
            # Remove from metadata
            for cache_key in entries_to_remove:
                del self.metadata["entries"][cache_key]
        
        self._save_metadata()
        self.logger.info(f"Cleared {cleared_count} cache entries")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = self.metadata["stats"].copy()
        stats["total_entries"] = len(self.metadata["entries"])
        stats["cache_size_mb"] = self._get_cache_size_mb()
        
        if stats["total_requests"] > 0:
            stats["hit_rate"] = stats["hits"] / stats["total_requests"]
        else:
            stats["hit_rate"] = 0.0
        
        return stats
    
    def _get_cache_size_mb(self) -> float:
        """Get total cache size in megabytes"""
        total_size = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                total_size += cache_file.stat().st_size
            except Exception:
                pass
        
        return total_size / (1024 * 1024)  # Convert to MB
    
    def optimize_cache(self):
        """Optimize cache by removing expired entries"""
        self.clear_cache(older_than_hours=self.cache_duration_hours)
        self.logger.info("Cache optimization completed")